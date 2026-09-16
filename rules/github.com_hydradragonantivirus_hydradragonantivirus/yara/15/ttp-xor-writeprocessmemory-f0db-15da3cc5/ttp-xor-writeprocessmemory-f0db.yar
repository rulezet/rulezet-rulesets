rule TTP_XOR_WriteProcessMemory_f0db {
  strings:
    $key_f0db = { a7 a9 [2] 95 8b [2] 93 be [2] bd be [2] 82 a2 }

  condition:
    any of them
}