rule TTP_XOR_WriteProcessMemory_a265 {
  strings:
    $key_a265 = { f5 17 [2] c7 35 [2] c1 00 [2] ef 00 [2] d0 1c }

  condition:
    any of them
}