rule TTP_XOR_WriteProcessMemory_4663 {
  strings:
    $key_4663 = { 11 11 [2] 23 33 [2] 25 06 [2] 0b 06 [2] 34 1a }

  condition:
    any of them
}