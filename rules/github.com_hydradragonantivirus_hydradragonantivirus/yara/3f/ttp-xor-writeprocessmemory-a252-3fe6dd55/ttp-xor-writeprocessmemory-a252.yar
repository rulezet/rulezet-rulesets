rule TTP_XOR_WriteProcessMemory_a252 {
  strings:
    $key_a252 = { f5 20 [2] c7 02 [2] c1 37 [2] ef 37 [2] d0 2b }

  condition:
    any of them
}