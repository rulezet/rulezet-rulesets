rule TTP_XOR_WriteProcessMemory_6649 {
  strings:
    $key_6649 = { 31 3b [2] 03 19 [2] 05 2c [2] 2b 2c [2] 14 30 }

  condition:
    any of them
}