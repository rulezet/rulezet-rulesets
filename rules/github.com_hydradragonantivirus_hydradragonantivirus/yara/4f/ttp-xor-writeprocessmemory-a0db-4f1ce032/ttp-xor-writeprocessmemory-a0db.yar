rule TTP_XOR_WriteProcessMemory_a0db {
  strings:
    $key_a0db = { f7 a9 [2] c5 8b [2] c3 be [2] ed be [2] d2 a2 }

  condition:
    any of them
}