rule TTP_XOR_WriteProcessMemory_e5db {
  strings:
    $key_e5db = { b2 a9 [2] 80 8b [2] 86 be [2] a8 be [2] 97 a2 }

  condition:
    any of them
}