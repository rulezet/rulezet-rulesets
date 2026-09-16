rule TTP_XOR_WriteProcessMemory_a5a6 {
  strings:
    $key_a5a6 = { f2 d4 [2] c0 f6 [2] c6 c3 [2] e8 c3 [2] d7 df }

  condition:
    any of them
}