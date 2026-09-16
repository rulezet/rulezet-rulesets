rule TTP_XOR_WriteProcessMemory_1462 {
  strings:
    $key_1462 = { 43 10 [2] 71 32 [2] 77 07 [2] 59 07 [2] 66 1b }

  condition:
    any of them
}