rule TTP_XOR_WriteProcessMemory_a264 {
  strings:
    $key_a264 = { f5 16 [2] c7 34 [2] c1 01 [2] ef 01 [2] d0 1d }

  condition:
    any of them
}