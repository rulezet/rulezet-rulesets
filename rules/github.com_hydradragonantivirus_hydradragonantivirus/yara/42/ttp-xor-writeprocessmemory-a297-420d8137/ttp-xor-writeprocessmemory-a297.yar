rule TTP_XOR_WriteProcessMemory_a297 {
  strings:
    $key_a297 = { f5 e5 [2] c7 c7 [2] c1 f2 [2] ef f2 [2] d0 ee }

  condition:
    any of them
}