rule TTP_XOR_WriteProcessMemory_a496 {
  strings:
    $key_a496 = { f3 e4 [2] c1 c6 [2] c7 f3 [2] e9 f3 [2] d6 ef }

  condition:
    any of them
}