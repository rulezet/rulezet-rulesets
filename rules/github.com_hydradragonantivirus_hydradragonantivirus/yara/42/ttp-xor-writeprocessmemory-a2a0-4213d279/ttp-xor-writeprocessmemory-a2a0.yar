rule TTP_XOR_WriteProcessMemory_a2a0 {
  strings:
    $key_a2a0 = { f5 d2 [2] c7 f0 [2] c1 c5 [2] ef c5 [2] d0 d9 }

  condition:
    any of them
}