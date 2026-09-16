rule TTP_XOR_WriteProcessMemory_a7db {
  strings:
    $key_a7db = { f0 a9 [2] c2 8b [2] c4 be [2] ea be [2] d5 a2 }

  condition:
    any of them
}