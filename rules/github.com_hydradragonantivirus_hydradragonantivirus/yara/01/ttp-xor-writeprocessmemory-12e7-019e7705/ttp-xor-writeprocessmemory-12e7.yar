rule TTP_XOR_WriteProcessMemory_12e7 {
  strings:
    $key_12e7 = { 45 95 [2] 77 b7 [2] 71 82 [2] 5f 82 [2] 60 9e }

  condition:
    any of them
}