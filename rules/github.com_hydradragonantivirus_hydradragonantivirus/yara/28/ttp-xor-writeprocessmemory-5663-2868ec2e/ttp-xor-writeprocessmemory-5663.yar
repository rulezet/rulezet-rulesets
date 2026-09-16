rule TTP_XOR_WriteProcessMemory_5663 {
  strings:
    $key_5663 = { 01 11 [2] 33 33 [2] 35 06 [2] 1b 06 [2] 24 1a }

  condition:
    any of them
}