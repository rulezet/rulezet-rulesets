rule TTP_XOR_WriteProcessMemory_1402 {
  strings:
    $key_1402 = { 43 70 [2] 71 52 [2] 77 67 [2] 59 67 [2] 66 7b }

  condition:
    any of them
}