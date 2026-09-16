rule TTP_XOR_WriteProcessMemory_40b9 {
  strings:
    $key_40b9 = { 17 cb [2] 25 e9 [2] 23 dc [2] 0d dc [2] 32 c0 }

  condition:
    any of them
}