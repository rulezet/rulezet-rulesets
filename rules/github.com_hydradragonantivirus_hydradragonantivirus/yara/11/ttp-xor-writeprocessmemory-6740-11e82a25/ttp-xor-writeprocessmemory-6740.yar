rule TTP_XOR_WriteProcessMemory_6740 {
  strings:
    $key_6740 = { 30 32 [2] 02 10 [2] 04 25 [2] 2a 25 [2] 15 39 }

  condition:
    any of them
}