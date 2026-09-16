rule TTP_XOR_WriteProcessMemory_1473 {
  strings:
    $key_1473 = { 43 01 [2] 71 23 [2] 77 16 [2] 59 16 [2] 66 0a }

  condition:
    any of them
}