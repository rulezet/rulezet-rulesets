rule TTP_XOR_WriteProcessMemory_c549 {
  strings:
    $key_c549 = { 92 3b [2] a0 19 [2] a6 2c [2] 88 2c [2] b7 30 }

  condition:
    any of them
}