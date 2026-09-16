rule TTP_XOR_WriteProcessMemory_1432 {
  strings:
    $key_1432 = { 43 40 [2] 71 62 [2] 77 57 [2] 59 57 [2] 66 4b }

  condition:
    any of them
}