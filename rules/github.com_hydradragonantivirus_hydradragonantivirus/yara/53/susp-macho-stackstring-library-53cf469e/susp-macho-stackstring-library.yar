rule SUSP_Macho_StackString_Library {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for the path /Library being passed as a stack string"

  strings:
    $slash_library = { 4? ?? 2f 4c 69 62 72 61 72 79 4? }      $library       = { 4? ?? 4c 69 62 72 61 72 79 4? }  
  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    1 of them
}