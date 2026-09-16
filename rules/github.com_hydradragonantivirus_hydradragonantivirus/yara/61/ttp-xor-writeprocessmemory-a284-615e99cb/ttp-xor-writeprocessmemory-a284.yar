rule TTP_XOR_WriteProcessMemory_a284 {
  strings:
    $key_a284 = { f5 f6 [2] c7 d4 [2] c1 e1 [2] ef e1 [2] d0 fd }

  condition:
    any of them
}