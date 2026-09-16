rule TTP_XOR_WriteProcessMemory_a210 {
  strings:
    $key_a210 = { f5 62 [2] c7 40 [2] c1 75 [2] ef 75 [2] d0 69 }

  condition:
    any of them
}