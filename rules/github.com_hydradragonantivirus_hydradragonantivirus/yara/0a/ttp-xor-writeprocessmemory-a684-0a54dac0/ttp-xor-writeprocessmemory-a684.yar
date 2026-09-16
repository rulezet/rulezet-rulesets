rule TTP_XOR_WriteProcessMemory_a684 {
  strings:
    $key_a684 = { f1 f6 [2] c3 d4 [2] c5 e1 [2] eb e1 [2] d4 fd }

  condition:
    any of them
}