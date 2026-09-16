rule TTP_XOR_WriteProcessMemory_a294 {
  strings:
    $key_a294 = { f5 e6 [2] c7 c4 [2] c1 f1 [2] ef f1 [2] d0 ed }

  condition:
    any of them
}