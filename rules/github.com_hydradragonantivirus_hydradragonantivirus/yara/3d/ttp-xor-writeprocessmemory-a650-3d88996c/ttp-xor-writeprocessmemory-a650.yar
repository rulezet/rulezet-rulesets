rule TTP_XOR_WriteProcessMemory_a650 {
  strings:
    $key_a650 = { f1 22 [2] c3 00 [2] c5 35 [2] eb 35 [2] d4 29 }

  condition:
    any of them
}