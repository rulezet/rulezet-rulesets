rule TTP_XOR_WriteProcessMemory_a502 {
  strings:
    $key_a502 = { f2 70 [2] c0 52 [2] c6 67 [2] e8 67 [2] d7 7b }

  condition:
    any of them
}