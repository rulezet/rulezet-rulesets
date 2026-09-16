rule TTP_XOR_WriteProcessMemory_a5c0 {
  strings:
    $key_a5c0 = { f2 b2 [2] c0 90 [2] c6 a5 [2] e8 a5 [2] d7 b9 }

  condition:
    any of them
}