rule TTP_XOR_WriteProcessMemory_e7db {
  strings:
    $key_e7db = { b0 a9 [2] 82 8b [2] 84 be [2] aa be [2] 95 a2 }

  condition:
    any of them
}