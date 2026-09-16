rule TTP_XOR_WriteProcessMemory_1451 {
  strings:
    $key_1451 = { 43 23 [2] 71 01 [2] 77 34 [2] 59 34 [2] 66 28 }

  condition:
    any of them
}