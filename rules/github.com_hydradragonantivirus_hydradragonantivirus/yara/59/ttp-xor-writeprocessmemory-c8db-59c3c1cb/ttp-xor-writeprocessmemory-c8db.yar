rule TTP_XOR_WriteProcessMemory_c8db {
  strings:
    $key_c8db = { 9f a9 [2] ad 8b [2] ab be [2] 85 be [2] ba a2 }

  condition:
    any of them
}