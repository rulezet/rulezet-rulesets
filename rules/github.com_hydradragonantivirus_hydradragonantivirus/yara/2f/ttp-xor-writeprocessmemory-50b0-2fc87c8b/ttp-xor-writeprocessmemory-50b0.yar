rule TTP_XOR_WriteProcessMemory_50b0 {
  strings:
    $key_50b0 = { 07 c2 [2] 35 e0 [2] 33 d5 [2] 1d d5 [2] 22 c9 }

  condition:
    any of them
}