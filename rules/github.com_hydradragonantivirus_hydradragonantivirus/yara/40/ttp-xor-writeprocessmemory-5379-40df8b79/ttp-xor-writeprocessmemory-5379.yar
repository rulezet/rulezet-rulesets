rule TTP_XOR_WriteProcessMemory_5379 {
  strings:
    $key_5379 = { 04 0b [2] 36 29 [2] 30 1c [2] 1e 1c [2] 21 00 }

  condition:
    any of them
}