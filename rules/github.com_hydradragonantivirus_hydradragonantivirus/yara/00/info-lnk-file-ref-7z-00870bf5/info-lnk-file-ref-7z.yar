rule INFO_LNK_File_Ref_7z {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference 7z"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "7z" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}