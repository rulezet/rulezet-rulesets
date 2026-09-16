rule TTP_XOR_WriteProcessMemory_d450 {
  strings:
    $key_d450 = { 83 22 [2] b1 00 [2] b7 35 [2] 99 35 [2] a6 29 }

  condition:
    any of them
}