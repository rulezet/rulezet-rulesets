rule TTP_XOR_WriteProcessMemory_b43d {
  strings:
    $key_b43d = { e3 4f [2] d1 6d [2] d7 58 [2] f9 58 [2] c6 44 }

  condition:
    any of them
}