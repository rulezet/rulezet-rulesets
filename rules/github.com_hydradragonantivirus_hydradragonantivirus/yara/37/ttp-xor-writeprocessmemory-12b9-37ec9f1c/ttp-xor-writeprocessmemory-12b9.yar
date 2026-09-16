rule TTP_XOR_WriteProcessMemory_12b9 {
  strings:
    $key_12b9 = { 45 cb [2] 77 e9 [2] 71 dc [2] 5f dc [2] 60 c0 }

  condition:
    any of them
}