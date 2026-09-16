rule TTP_XOR_WriteProcessMemory_b0db {
  strings:
    $key_b0db = { e7 a9 [2] d5 8b [2] d3 be [2] fd be [2] c2 a2 }

  condition:
    any of them
}