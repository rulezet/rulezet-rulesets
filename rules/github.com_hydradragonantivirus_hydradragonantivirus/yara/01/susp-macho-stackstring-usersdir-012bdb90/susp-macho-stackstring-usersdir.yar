rule SUSP_Macho_StackString_UsersDir {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for the path /Users/ being passed as a stack string"

  strings:
    $users_dir = { 4? ?? 2f 55 73 65 72 73 2f 4? }  
  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    1 of them
}