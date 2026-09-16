rule TTP_XOR_WriteProcessMemory_0549 {
  strings:
    $key_0549 = { 52 3b [2] 60 19 [2] 66 2c [2] 48 2c [2] 77 30 }

  condition:
    any of them
}