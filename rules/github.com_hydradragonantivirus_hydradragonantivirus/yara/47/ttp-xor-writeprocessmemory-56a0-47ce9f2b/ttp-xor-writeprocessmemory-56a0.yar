rule TTP_XOR_WriteProcessMemory_56a0 {
  strings:
    $key_56a0 = { 01 d2 [2] 33 f0 [2] 35 c5 [2] 1b c5 [2] 24 d9 }

  condition:
    any of them
}