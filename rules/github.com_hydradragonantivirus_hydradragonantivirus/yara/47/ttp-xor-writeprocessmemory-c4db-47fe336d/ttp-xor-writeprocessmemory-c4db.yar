rule TTP_XOR_WriteProcessMemory_c4db {
  strings:
    $key_c4db = { 93 a9 [2] a1 8b [2] a7 be [2] 89 be [2] b6 a2 }

  condition:
    any of them
}