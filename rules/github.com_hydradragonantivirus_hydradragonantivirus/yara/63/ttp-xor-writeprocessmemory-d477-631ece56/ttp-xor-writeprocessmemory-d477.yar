rule TTP_XOR_WriteProcessMemory_d477 {
  strings:
    $key_d477 = { 83 05 [2] b1 27 [2] b7 12 [2] 99 12 [2] a6 0e }

  condition:
    any of them
}