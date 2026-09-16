rule TTP_XOR_WriteProcessMemory_a526 {
  strings:
    $key_a526 = { f2 54 [2] c0 76 [2] c6 43 [2] e8 43 [2] d7 5f }

  condition:
    any of them
}