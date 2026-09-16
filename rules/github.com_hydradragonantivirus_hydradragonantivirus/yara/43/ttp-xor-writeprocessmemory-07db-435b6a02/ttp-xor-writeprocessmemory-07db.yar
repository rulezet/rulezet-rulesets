rule TTP_XOR_WriteProcessMemory_07db {
  strings:
    $key_07db = { 50 a9 [2] 62 8b [2] 64 be [2] 4a be [2] 75 a2 }

  condition:
    any of them
}