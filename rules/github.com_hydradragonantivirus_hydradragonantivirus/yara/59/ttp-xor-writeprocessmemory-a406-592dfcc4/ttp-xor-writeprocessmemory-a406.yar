rule TTP_XOR_WriteProcessMemory_a406 {
  strings:
    $key_a406 = { f3 74 [2] c1 56 [2] c7 63 [2] e9 63 [2] d6 7f }

  condition:
    any of them
}