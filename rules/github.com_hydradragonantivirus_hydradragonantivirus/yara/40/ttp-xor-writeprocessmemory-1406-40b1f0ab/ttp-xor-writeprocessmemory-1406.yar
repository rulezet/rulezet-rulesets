rule TTP_XOR_WriteProcessMemory_1406 {
  strings:
    $key_1406 = { 43 74 [2] 71 56 [2] 77 63 [2] 59 63 [2] 66 7f }

  condition:
    any of them
}