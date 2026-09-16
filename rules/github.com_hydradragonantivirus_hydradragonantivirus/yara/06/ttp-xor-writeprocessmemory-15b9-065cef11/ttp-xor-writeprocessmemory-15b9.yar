rule TTP_XOR_WriteProcessMemory_15b9 {
  strings:
    $key_15b9 = { 42 cb [2] 70 e9 [2] 76 dc [2] 58 dc [2] 67 c0 }

  condition:
    any of them
}