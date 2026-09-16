rule TTP_XOR_WriteProcessMemory_1467 {
  strings:
    $key_1467 = { 43 15 [2] 71 37 [2] 77 02 [2] 59 02 [2] 66 1e }

  condition:
    any of them
}