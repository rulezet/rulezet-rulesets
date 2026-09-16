rule TTP_XOR_WriteProcessMemory_a410 {
  strings:
    $key_a410 = { f3 62 [2] c1 40 [2] c7 75 [2] e9 75 [2] d6 69 }

  condition:
    any of them
}