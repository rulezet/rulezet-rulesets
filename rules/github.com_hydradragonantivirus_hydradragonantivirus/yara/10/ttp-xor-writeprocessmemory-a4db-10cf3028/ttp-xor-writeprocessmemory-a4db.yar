rule TTP_XOR_WriteProcessMemory_a4db {
  strings:
    $key_a4db = { f3 a9 [2] c1 8b [2] c7 be [2] e9 be [2] d6 a2 }

  condition:
    any of them
}