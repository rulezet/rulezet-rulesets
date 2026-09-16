rule TTP_XOR_WriteProcessMemory_5640 {
  strings:
    $key_5640 = { 01 32 [2] 33 10 [2] 35 25 [2] 1b 25 [2] 24 39 }

  condition:
    any of them
}