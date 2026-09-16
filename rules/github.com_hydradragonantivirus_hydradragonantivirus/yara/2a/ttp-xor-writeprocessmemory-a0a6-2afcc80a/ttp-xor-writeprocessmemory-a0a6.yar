rule TTP_XOR_WriteProcessMemory_a0a6 {
  strings:
    $key_a0a6 = { f7 d4 [2] c5 f6 [2] c3 c3 [2] ed c3 [2] d2 df }

  condition:
    any of them
}