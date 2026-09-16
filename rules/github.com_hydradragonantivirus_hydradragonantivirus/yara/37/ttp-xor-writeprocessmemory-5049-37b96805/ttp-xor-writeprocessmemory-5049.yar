rule TTP_XOR_WriteProcessMemory_5049 {
  strings:
    $key_5049 = { 07 3b [2] 35 19 [2] 33 2c [2] 1d 2c [2] 22 30 }

  condition:
    any of them
}