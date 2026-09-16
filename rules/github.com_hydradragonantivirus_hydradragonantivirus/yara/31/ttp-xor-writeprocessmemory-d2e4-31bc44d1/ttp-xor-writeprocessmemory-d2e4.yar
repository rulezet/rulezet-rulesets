rule TTP_XOR_WriteProcessMemory_d2e4 {
  strings:
    $key_d2e4 = { 85 96 [2] b7 b4 [2] b1 81 [2] 9f 81 [2] a0 9d }

  condition:
    any of them
}