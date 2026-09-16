rule SUSP_Macho_StackString_rmrf_Cmd {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for the string rm -rf being passed as a stack string"

  strings:
    $rm_rf_stack = { 4? ?? 72 6d 20 2d 72 66 4? }  
  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    1 of them
}