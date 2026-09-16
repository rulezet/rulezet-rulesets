rule TTP_XOR_WriteProcessMemory_a212 {
  strings:
    $key_a212 = { f5 60 [2] c7 42 [2] c1 77 [2] ef 77 [2] d0 6b }

  condition:
    any of them
}