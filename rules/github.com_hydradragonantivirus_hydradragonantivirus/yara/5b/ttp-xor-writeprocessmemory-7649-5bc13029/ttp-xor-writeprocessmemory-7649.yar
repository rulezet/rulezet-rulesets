rule TTP_XOR_WriteProcessMemory_7649 {
  strings:
    $key_7649 = { 21 3b [2] 13 19 [2] 15 2c [2] 3b 2c [2] 04 30 }

  condition:
    any of them
}