rule TTP_XOR_WriteProcessMemory_a277 {
  strings:
    $key_a277 = { f5 05 [2] c7 27 [2] c1 12 [2] ef 12 [2] d0 0e }

  condition:
    any of them
}