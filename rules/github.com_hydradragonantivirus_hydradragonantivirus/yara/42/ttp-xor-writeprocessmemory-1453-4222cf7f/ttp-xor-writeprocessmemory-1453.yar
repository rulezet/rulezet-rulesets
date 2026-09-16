rule TTP_XOR_WriteProcessMemory_1453 {
  strings:
    $key_1453 = { 43 21 [2] 71 03 [2] 77 36 [2] 59 36 [2] 66 2a }

  condition:
    any of them
}