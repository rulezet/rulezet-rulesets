rule TTP_XOR_WriteProcessMemory_56a5 {
  strings:
    $key_56a5 = { 01 d7 [2] 33 f5 [2] 35 c0 [2] 1b c0 [2] 24 dc }

  condition:
    any of them
}