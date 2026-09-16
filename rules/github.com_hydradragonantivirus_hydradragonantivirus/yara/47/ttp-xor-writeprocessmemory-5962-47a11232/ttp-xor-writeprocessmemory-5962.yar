rule TTP_XOR_WriteProcessMemory_5962 {
  strings:
    $key_5962 = { 0e 10 [2] 3c 32 [2] 3a 07 [2] 14 07 [2] 2b 1b }

  condition:
    any of them
}