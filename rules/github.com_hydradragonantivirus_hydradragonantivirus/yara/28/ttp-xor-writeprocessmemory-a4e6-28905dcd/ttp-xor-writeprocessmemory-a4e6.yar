rule TTP_XOR_WriteProcessMemory_a4e6 {
  strings:
    $key_a4e6 = { f3 94 [2] c1 b6 [2] c7 83 [2] e9 83 [2] d6 9f }

  condition:
    any of them
}