rule TTP_XOR_WriteProcessMemory_6749 {
  strings:
    $key_6749 = { 30 3b [2] 02 19 [2] 04 2c [2] 2a 2c [2] 15 30 }

  condition:
    any of them
}