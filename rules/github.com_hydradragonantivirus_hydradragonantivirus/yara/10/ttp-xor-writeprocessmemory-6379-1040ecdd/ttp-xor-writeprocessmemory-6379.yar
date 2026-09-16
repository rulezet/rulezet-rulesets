rule TTP_XOR_WriteProcessMemory_6379 {
  strings:
    $key_6379 = { 34 0b [2] 06 29 [2] 00 1c [2] 2e 1c [2] 11 00 }

  condition:
    any of them
}