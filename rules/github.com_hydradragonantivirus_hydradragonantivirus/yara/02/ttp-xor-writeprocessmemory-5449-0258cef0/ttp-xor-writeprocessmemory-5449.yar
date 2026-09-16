rule TTP_XOR_WriteProcessMemory_5449 {
  strings:
    $key_5449 = { 03 3b [2] 31 19 [2] 37 2c [2] 19 2c [2] 26 30 }

  condition:
    any of them
}