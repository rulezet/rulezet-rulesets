rule TTP_XOR_WriteProcessMemory_14b9 {
  strings:
    $key_14b9 = { 43 cb [2] 71 e9 [2] 77 dc [2] 59 dc [2] 66 c0 }

  condition:
    any of them
}