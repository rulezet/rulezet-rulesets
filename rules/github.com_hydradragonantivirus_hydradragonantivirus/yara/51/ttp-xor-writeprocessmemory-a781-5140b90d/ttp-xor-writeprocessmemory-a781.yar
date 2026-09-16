rule TTP_XOR_WriteProcessMemory_a781 {
  strings:
    $key_a781 = { f0 f3 [2] c2 d1 [2] c4 e4 [2] ea e4 [2] d5 f8 }

  condition:
    any of them
}