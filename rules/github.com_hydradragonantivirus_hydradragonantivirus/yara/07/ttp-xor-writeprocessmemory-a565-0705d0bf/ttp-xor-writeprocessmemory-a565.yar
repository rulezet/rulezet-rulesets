rule TTP_XOR_WriteProcessMemory_a565 {
  strings:
    $key_a565 = { f2 17 [2] c0 35 [2] c6 00 [2] e8 00 [2] d7 1c }

  condition:
    any of them
}