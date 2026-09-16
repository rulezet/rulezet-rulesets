rule TTP_XOR_WriteProcessMemory_5723 {
  strings:
    $key_5723 = { 00 51 [2] 32 73 [2] 34 46 [2] 1a 46 [2] 25 5a }

  condition:
    any of them
}