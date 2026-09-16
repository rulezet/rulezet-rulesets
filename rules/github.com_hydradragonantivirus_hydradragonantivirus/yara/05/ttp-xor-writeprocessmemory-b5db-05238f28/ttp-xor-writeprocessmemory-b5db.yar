rule TTP_XOR_WriteProcessMemory_b5db {
  strings:
    $key_b5db = { e2 a9 [2] d0 8b [2] d6 be [2] f8 be [2] c7 a2 }

  condition:
    any of them
}