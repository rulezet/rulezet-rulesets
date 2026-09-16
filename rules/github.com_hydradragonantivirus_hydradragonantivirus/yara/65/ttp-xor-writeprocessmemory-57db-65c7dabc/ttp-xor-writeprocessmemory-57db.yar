rule TTP_XOR_WriteProcessMemory_57db {
  strings:
    $key_57db = { 00 a9 [2] 32 8b [2] 34 be [2] 1a be [2] 25 a2 }

  condition:
    any of them
}