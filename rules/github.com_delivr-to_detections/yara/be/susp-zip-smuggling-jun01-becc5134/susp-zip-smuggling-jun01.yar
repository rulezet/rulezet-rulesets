rule SUSP_ZIP_Smuggling_Jun01
{
    meta:
        description = "ZIP archives with data smuggled between last file record and the central directory."
        author = "delivr.to"
        date = "2025-06-01"
        score = 60
        reference = "https://github.com/Octoberfest7/zip_smuggling/"
    strings:
        $lfh  = { 50 4B 03 04 }                    $eocd = { 50 4B 05 06 }            
    condition:
                uint32(0) == 0x04034b50 and

                #lfh > 0 and
        #lfh <= 10 and
        #eocd == 1 and

                uint16(@lfh[#lfh] + 26) <= 256 and
        uint16(@lfh[#lfh] + 28) <= 256 and

                uint32(@lfh[#lfh] + 18) > 0 and
        uint32(@lfh[#lfh] + 18) < 100000000 and

                uint32(@eocd[1] + 16) > @lfh[#lfh] and 

                                                (
            uint32(@eocd[1] + 16) - (
                @lfh[#lfh] +
                30 +
                uint16(@lfh[#lfh] + 26) +
                uint16(@lfh[#lfh] + 28) +
                uint32(@lfh[#lfh] + 18)
            )
        ) > 64
}