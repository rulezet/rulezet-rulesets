rule TTP_XOR_WriteProcessMemory_b3db {
  strings:
    $key_b3db = { e4 a9 [2] d6 8b [2] d0 be [2] fe be [2] c1 a2 }

  condition:
    any of them
}