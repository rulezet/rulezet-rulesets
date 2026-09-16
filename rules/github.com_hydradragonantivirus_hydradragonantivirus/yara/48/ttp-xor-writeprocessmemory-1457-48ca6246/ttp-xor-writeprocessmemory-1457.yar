rule TTP_XOR_WriteProcessMemory_1457 {
  strings:
    $key_1457 = { 43 25 [2] 71 07 [2] 77 32 [2] 59 32 [2] 66 2e }

  condition:
    any of them
}