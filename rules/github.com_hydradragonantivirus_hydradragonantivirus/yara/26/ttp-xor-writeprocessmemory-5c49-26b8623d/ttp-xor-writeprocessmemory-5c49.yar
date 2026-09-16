rule TTP_XOR_WriteProcessMemory_5c49 {
  strings:
    $key_5c49 = { 0b 3b [2] 39 19 [2] 3f 2c [2] 11 2c [2] 2e 30 }

  condition:
    any of them
}