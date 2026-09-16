rule TTP_XOR_WriteProcessMemory_a651 {
  strings:
    $key_a651 = { f1 23 [2] c3 01 [2] c5 34 [2] eb 34 [2] d4 28 }

  condition:
    any of them
}