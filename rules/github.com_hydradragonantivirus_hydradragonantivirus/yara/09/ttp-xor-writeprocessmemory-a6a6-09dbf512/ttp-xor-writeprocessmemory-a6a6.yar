rule TTP_XOR_WriteProcessMemory_a6a6 {
  strings:
    $key_a6a6 = { f1 d4 [2] c3 f6 [2] c5 c3 [2] eb c3 [2] d4 df }

  condition:
    any of them
}