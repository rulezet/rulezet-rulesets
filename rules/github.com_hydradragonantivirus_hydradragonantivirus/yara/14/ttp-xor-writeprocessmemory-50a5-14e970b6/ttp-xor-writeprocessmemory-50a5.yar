rule TTP_XOR_WriteProcessMemory_50a5 {
  strings:
    $key_50a5 = { 07 d7 [2] 35 f5 [2] 33 c0 [2] 1d c0 [2] 22 dc }

  condition:
    any of them
}