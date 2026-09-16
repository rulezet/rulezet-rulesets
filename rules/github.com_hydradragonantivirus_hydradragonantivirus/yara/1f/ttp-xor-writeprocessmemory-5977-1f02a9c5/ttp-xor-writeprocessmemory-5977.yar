rule TTP_XOR_WriteProcessMemory_5977 {
  strings:
    $key_5977 = { 0e 05 [2] 3c 27 [2] 3a 12 [2] 14 12 [2] 2b 0e }

  condition:
    any of them
}