rule SUSP_ZIP_Smuggling_Egg_Jun01
{
    meta:
        description = "ZIP archives with known egghunter byte sequence from Octoberfest7 zip_smuggling tool between end of file content and central directory."
        author = "delivr.to"
        date = "2025-06-01"
        score = 75
        reference = "https://github.com/Octoberfest7/zip_smuggling/"
    strings:
        $lfh  = { 50 4B 03 04 }                    $eocd = { 50 4B 05 06 }                    $egg  = { 55 55 55 55 }            
    condition:
                uint32(0) == 0x04034b50 and

                #lfh > 0 and
        #lfh <= 10 and
        #eocd == 1 and
        
                #egg > 0 and

                                $egg in (
            @lfh[#lfh] + 30 + uint16(@lfh[#lfh] + 26) + uint16(@lfh[#lfh] + 28) + uint32(@lfh[#lfh] + 18)
            ..
            uint32(@eocd[1] + 16)
        )
}