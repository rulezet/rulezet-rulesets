rule INFO_LNK_File_Ref_java {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference java"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "java" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}