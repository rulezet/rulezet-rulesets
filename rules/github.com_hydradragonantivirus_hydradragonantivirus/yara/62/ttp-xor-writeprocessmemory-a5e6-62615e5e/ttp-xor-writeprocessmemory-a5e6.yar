rule TTP_XOR_WriteProcessMemory_a5e6 {
  strings:
    $key_a5e6 = { f2 94 [2] c0 b6 [2] c6 83 [2] e8 83 [2] d7 9f }

  condition:
    any of them
}