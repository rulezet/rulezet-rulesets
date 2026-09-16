rule TTP_XOR_WriteProcessMemory_c1db {
  strings:
    $key_c1db = { 96 a9 [2] a4 8b [2] a2 be [2] 8c be [2] b3 a2 }

  condition:
    any of them
}