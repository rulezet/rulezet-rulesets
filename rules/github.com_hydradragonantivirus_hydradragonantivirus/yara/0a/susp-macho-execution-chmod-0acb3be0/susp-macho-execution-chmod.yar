rule SUSP_Macho_Execution_CHMOD
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-02-01"
        version = "1.0"
        description = "checking Macho files for additional execution strings like chmod to mark files as executable"

    strings:
        $ = "chmod + x" ascii wide
        $ = "chmod +x" ascii wide
        $ = "chmod+x" ascii wide
    condition:
        (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
        and any of them
}