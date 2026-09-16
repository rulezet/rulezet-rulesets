rule TTP_XOR_WriteProcessMemory_a280 {
  strings:
    $key_a280 = { f5 f2 [2] c7 d0 [2] c1 e5 [2] ef e5 [2] d0 f9 }

  condition:
    any of them
}