rule TTP_XOR_WriteProcessMemory_d4e4 {
  strings:
    $key_d4e4 = { 83 96 [2] b1 b4 [2] b7 81 [2] 99 81 [2] a6 9d }

  condition:
    any of them
}