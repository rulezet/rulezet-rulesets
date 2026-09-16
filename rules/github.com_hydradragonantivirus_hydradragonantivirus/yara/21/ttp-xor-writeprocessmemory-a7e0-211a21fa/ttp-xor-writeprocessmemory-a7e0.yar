rule TTP_XOR_WriteProcessMemory_a7e0 {
  strings:
    $key_a7e0 = { f0 92 [2] c2 b0 [2] c4 85 [2] ea 85 [2] d5 99 }

  condition:
    any of them
}