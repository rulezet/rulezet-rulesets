rule TTP_XOR_WriteProcessMemory_e1db {
  strings:
    $key_e1db = { b6 a9 [2] 84 8b [2] 82 be [2] ac be [2] 93 a2 }

  condition:
    any of them
}