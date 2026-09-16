rule TTP_XOR_WriteProcessMemory_a273 {
  strings:
    $key_a273 = { f5 01 [2] c7 23 [2] c1 16 [2] ef 16 [2] d0 0a }

  condition:
    any of them
}