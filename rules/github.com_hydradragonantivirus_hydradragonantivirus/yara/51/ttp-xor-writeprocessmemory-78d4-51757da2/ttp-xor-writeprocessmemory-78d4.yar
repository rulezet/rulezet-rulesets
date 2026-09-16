rule TTP_XOR_WriteProcessMemory_78d4 {
  strings:
    $key_78d4 = { 2f a6 [2] 1d 84 [2] 1b b1 [2] 35 b1 [2] 0a ad }

  condition:
    any of them
}