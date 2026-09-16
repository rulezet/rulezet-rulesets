rule TTP_XOR_WriteProcessMemory_1449 {
  strings:
    $key_1449 = { 43 3b [2] 71 19 [2] 77 2c [2] 59 2c [2] 66 30 }

  condition:
    any of them
}