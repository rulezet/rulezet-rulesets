rule TTP_XOR_WriteProcessMemory_a692 {
  strings:
    $key_a692 = { f1 e0 [2] c3 c2 [2] c5 f7 [2] eb f7 [2] d4 eb }

  condition:
    any of them
}