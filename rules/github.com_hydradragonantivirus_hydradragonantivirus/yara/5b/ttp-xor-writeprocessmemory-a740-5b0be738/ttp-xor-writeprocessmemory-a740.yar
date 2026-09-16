rule TTP_XOR_WriteProcessMemory_a740 {
  strings:
    $key_a740 = { f0 32 [2] c2 10 [2] c4 25 [2] ea 25 [2] d5 39 }

  condition:
    any of them
}