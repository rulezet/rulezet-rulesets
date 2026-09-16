rule TTP_XOR_WriteProcessMemory_a504 {
  strings:
    $key_a504 = { f2 76 [2] c0 54 [2] c6 61 [2] e8 61 [2] d7 7d }

  condition:
    any of them
}