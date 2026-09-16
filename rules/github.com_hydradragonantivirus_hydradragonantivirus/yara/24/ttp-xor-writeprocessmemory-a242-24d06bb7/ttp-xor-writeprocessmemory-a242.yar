rule TTP_XOR_WriteProcessMemory_a242 {
  strings:
    $key_a242 = { f5 30 [2] c7 12 [2] c1 27 [2] ef 27 [2] d0 3b }

  condition:
    any of them
}