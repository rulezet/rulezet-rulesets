rule TTP_XOR_WriteProcessMemory_d461 {
  strings:
    $key_d461 = { 83 13 [2] b1 31 [2] b7 04 [2] 99 04 [2] a6 18 }

  condition:
    any of them
}