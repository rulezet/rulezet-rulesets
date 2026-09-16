rule TTP_XOR_WriteProcessMemory_a2d9 {
  strings:
    $key_a2d9 = { f5 ab [2] c7 89 [2] c1 bc [2] ef bc [2] d0 a0 }

  condition:
    any of them
}