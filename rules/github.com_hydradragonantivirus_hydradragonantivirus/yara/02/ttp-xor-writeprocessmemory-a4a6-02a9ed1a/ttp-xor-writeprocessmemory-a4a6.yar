rule TTP_XOR_WriteProcessMemory_a4a6 {
  strings:
    $key_a4a6 = { f3 d4 [2] c1 f6 [2] c7 c3 [2] e9 c3 [2] d6 df }

  condition:
    any of them
}