rule TTP_XOR_WriteProcessMemory_7249 {
  strings:
    $key_7249 = { 25 3b [2] 17 19 [2] 11 2c [2] 3f 2c [2] 00 30 }

  condition:
    any of them
}