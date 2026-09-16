rule TTP_XOR_WriteProcessMemory_1400 {
  strings:
    $key_1400 = { 43 72 [2] 71 50 [2] 77 65 [2] 59 65 [2] 66 79 }

  condition:
    any of them
}