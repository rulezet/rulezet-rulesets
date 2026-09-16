rule TTP_XOR_WriteProcessMemory_02b9 {
  strings:
    $key_02b9 = { 55 cb [2] 67 e9 [2] 61 dc [2] 4f dc [2] 70 c0 }

  condition:
    any of them
}