rule TTP_XOR_WriteProcessMemory_d474 {
  strings:
    $key_d474 = { 83 06 [2] b1 24 [2] b7 11 [2] 99 11 [2] a6 0d }

  condition:
    any of them
}