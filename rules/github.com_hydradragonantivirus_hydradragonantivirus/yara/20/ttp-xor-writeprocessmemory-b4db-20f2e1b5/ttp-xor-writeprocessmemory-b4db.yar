rule TTP_XOR_WriteProcessMemory_b4db {
  strings:
    $key_b4db = { e3 a9 [2] d1 8b [2] d7 be [2] f9 be [2] c6 a2 }

  condition:
    any of them
}