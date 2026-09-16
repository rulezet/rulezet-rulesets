rule TTP_XOR_WriteProcessMemory_96db {
  strings:
    $key_96db = { c1 a9 [2] f3 8b [2] f5 be [2] db be [2] e4 a2 }

  condition:
    any of them
}