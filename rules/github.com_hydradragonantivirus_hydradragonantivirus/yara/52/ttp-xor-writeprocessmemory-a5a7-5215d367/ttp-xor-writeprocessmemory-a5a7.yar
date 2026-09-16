rule TTP_XOR_WriteProcessMemory_a5a7 {
  strings:
    $key_a5a7 = { f2 d5 [2] c0 f7 [2] c6 c2 [2] e8 c2 [2] d7 de }

  condition:
    any of them
}