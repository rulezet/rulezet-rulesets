rule TTP_XOR_WriteProcessMemory_a222 {
  strings:
    $key_a222 = { f5 50 [2] c7 72 [2] c1 47 [2] ef 47 [2] d0 5b }

  condition:
    any of them
}