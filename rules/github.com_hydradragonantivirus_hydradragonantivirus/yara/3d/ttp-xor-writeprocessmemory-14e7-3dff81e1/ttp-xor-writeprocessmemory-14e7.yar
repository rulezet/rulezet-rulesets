rule TTP_XOR_WriteProcessMemory_14e7 {
  strings:
    $key_14e7 = { 43 95 [2] 71 b7 [2] 77 82 [2] 59 82 [2] 66 9e }

  condition:
    any of them
}