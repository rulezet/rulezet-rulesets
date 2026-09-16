rule TTP_XOR_WriteProcessMemory_a451 {
  strings:
    $key_a451 = { f3 23 [2] c1 01 [2] c7 34 [2] e9 34 [2] d6 28 }

  condition:
    any of them
}