rule TTP_XOR_WriteProcessMemory_e949 {
  strings:
    $key_e949 = { be 3b [2] 8c 19 [2] 8a 2c [2] a4 2c [2] 9b 30 }

  condition:
    any of them
}