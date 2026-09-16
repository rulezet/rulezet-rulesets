rule TTP_XOR_WriteProcessMemory_d2db {
  strings:
    $key_d2db = { 85 a9 [2] b7 8b [2] b1 be [2] 9f be [2] a0 a2 }

  condition:
    any of them
}