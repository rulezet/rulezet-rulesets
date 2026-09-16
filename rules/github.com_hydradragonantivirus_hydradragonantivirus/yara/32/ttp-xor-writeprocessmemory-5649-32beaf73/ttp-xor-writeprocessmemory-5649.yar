rule TTP_XOR_WriteProcessMemory_5649 {
  strings:
    $key_5649 = { 01 3b [2] 33 19 [2] 35 2c [2] 1b 2c [2] 24 30 }

  condition:
    any of them
}