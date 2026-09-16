rule TTP_XOR_WriteProcessMemory_4049 {
  strings:
    $key_4049 = { 17 3b [2] 25 19 [2] 23 2c [2] 0d 2c [2] 32 30 }

  condition:
    any of them
}