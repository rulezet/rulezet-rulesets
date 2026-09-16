rule TTP_XOR_WriteProcessMemory_5643 {
  strings:
    $key_5643 = { 01 31 [2] 33 13 [2] 35 26 [2] 1b 26 [2] 24 3a }

  condition:
    any of them
}