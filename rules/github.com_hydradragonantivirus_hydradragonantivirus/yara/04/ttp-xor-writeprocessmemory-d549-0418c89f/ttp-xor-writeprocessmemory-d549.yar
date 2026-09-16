rule TTP_XOR_WriteProcessMemory_d549 {
  strings:
    $key_d549 = { 82 3b [2] b0 19 [2] b6 2c [2] 98 2c [2] a7 30 }

  condition:
    any of them
}