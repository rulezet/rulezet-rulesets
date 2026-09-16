rule TTP_XOR_WriteProcessMemory_50e1 {
  strings:
    $key_50e1 = { 07 93 [2] 35 b1 [2] 33 84 [2] 1d 84 [2] 22 98 }

  condition:
    any of them
}