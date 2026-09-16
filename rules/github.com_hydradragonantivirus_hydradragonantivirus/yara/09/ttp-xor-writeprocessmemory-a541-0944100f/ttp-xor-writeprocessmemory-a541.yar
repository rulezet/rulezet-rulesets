rule TTP_XOR_WriteProcessMemory_a541 {
  strings:
    $key_a541 = { f2 33 [2] c0 11 [2] c6 24 [2] e8 24 [2] d7 38 }

  condition:
    any of them
}