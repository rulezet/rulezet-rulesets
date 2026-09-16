rule TTP_XOR_WriteProcessMemory_5149 {
  strings:
    $key_5149 = { 06 3b [2] 34 19 [2] 32 2c [2] 1c 2c [2] 23 30 }

  condition:
    any of them
}