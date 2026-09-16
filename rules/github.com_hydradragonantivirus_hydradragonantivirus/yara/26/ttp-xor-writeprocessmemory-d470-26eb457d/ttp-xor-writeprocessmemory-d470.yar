rule TTP_XOR_WriteProcessMemory_d470 {
  strings:
    $key_d470 = { 83 02 [2] b1 20 [2] b7 15 [2] 99 15 [2] a6 09 }

  condition:
    any of them
}