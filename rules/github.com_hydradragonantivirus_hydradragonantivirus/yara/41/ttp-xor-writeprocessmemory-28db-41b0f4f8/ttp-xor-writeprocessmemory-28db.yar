rule TTP_XOR_WriteProcessMemory_28db {
  strings:
    $key_28db = { 7f a9 [2] 4d 8b [2] 4b be [2] 65 be [2] 5a a2 }

  condition:
    any of them
}