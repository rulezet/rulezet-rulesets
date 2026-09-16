rule TTP_XOR_WriteProcessMemory_a755 {
  strings:
    $key_a755 = { f0 27 [2] c2 05 [2] c4 30 [2] ea 30 [2] d5 2c }

  condition:
    any of them
}