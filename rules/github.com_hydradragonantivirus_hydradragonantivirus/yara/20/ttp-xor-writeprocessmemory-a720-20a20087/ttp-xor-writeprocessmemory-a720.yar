rule TTP_XOR_WriteProcessMemory_a720 {
  strings:
    $key_a720 = { f0 52 [2] c2 70 [2] c4 45 [2] ea 45 [2] d5 59 }

  condition:
    any of them
}