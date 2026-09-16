rule TTP_XOR_WriteProcessMemory_d4c4 {
  strings:
    $key_d4c4 = { 83 b6 [2] b1 94 [2] b7 a1 [2] 99 a1 [2] a6 bd }

  condition:
    any of them
}