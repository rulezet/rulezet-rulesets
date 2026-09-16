rule TTP_XOR_WriteProcessMemory_d302 {
  strings:
    $key_d302 = { 84 70 [2] b6 52 [2] b0 67 [2] 9e 67 [2] a1 7b }

  condition:
    any of them
}