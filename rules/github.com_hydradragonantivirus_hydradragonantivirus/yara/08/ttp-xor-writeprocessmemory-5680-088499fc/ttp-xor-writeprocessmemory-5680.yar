rule TTP_XOR_WriteProcessMemory_5680 {
  strings:
    $key_5680 = { 01 f2 [2] 33 d0 [2] 35 e5 [2] 1b e5 [2] 24 f9 }

  condition:
    any of them
}