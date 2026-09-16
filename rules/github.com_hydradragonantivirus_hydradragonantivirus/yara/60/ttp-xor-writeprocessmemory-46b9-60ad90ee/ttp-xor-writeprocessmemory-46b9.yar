rule TTP_XOR_WriteProcessMemory_46b9 {
  strings:
    $key_46b9 = { 11 cb [2] 23 e9 [2] 25 dc [2] 0b dc [2] 34 c0 }

  condition:
    any of them
}