rule TTP_XOR_WriteProcessMemory_68db {
  strings:
    $key_68db = { 3f a9 [2] 0d 8b [2] 0b be [2] 25 be [2] 1a a2 }

  condition:
    any of them
}