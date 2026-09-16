rule TTP_XOR_WriteProcessMemory_2649 {
  strings:
    $key_2649 = { 71 3b [2] 43 19 [2] 45 2c [2] 6b 2c [2] 54 30 }

  condition:
    any of them
}