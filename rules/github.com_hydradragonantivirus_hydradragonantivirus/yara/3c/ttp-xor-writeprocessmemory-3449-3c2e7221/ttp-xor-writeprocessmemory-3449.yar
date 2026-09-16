rule TTP_XOR_WriteProcessMemory_3449 {
  strings:
    $key_3449 = { 63 3b [2] 51 19 [2] 57 2c [2] 79 2c [2] 46 30 }

  condition:
    any of them
}