rule TTP_XOR_WriteProcessMemory_1649 {
  strings:
    $key_1649 = { 41 3b [2] 73 19 [2] 75 2c [2] 5b 2c [2] 64 30 }

  condition:
    any of them
}