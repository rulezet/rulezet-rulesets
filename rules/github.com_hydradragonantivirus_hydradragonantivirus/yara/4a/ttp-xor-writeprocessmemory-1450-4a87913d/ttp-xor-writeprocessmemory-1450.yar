rule TTP_XOR_WriteProcessMemory_1450 {
  strings:
    $key_1450 = { 43 22 [2] 71 00 [2] 77 35 [2] 59 35 [2] 66 29 }

  condition:
    any of them
}