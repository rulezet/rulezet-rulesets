rule TTP_XOR_WriteProcessMemory_1200 {
  strings:
    $key_1200 = { 45 72 [2] 77 50 [2] 71 65 [2] 5f 65 [2] 60 79 }

  condition:
    any of them
}