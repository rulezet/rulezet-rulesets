rule TTP_XOR_WriteProcessMemory_5960 {
  strings:
    $key_5960 = { 0e 12 [2] 3c 30 [2] 3a 05 [2] 14 05 [2] 2b 19 }

  condition:
    any of them
}