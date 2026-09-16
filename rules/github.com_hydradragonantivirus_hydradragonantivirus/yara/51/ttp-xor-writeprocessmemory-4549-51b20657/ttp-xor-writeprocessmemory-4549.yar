rule TTP_XOR_WriteProcessMemory_4549 {
  strings:
    $key_4549 = { 12 3b [2] 20 19 [2] 26 2c [2] 08 2c [2] 37 30 }

  condition:
    any of them
}