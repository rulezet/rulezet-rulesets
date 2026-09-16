rule TTP_XOR_WriteProcessMemory_71db {
  strings:
    $key_71db = { 26 a9 [2] 14 8b [2] 12 be [2] 3c be [2] 03 a2 }

  condition:
    any of them
}