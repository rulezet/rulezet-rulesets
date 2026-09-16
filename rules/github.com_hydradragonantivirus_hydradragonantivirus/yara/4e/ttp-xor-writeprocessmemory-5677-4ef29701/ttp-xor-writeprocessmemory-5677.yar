rule TTP_XOR_WriteProcessMemory_5677 {
  strings:
    $key_5677 = { 01 05 [2] 33 27 [2] 35 12 [2] 1b 12 [2] 24 0e }

  condition:
    any of them
}