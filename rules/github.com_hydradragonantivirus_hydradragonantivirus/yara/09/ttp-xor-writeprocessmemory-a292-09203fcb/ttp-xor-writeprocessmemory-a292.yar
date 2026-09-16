rule TTP_XOR_WriteProcessMemory_a292 {
  strings:
    $key_a292 = { f5 e0 [2] c7 c2 [2] c1 f7 [2] ef f7 [2] d0 eb }

  condition:
    any of them
}