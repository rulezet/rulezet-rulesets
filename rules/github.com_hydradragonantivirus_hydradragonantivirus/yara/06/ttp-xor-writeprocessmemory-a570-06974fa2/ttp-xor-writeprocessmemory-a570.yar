rule TTP_XOR_WriteProcessMemory_a570 {
  strings:
    $key_a570 = { f2 02 [2] c0 20 [2] c6 15 [2] e8 15 [2] d7 09 }

  condition:
    any of them
}