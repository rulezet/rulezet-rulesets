rule TTP_XOR_WriteProcessMemory_78a6 {
  strings:
    $key_78a6 = { 2f d4 [2] 1d f6 [2] 1b c3 [2] 35 c3 [2] 0a df }

  condition:
    any of them
}