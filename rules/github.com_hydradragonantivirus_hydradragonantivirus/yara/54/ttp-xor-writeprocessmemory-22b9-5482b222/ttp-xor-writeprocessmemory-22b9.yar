rule TTP_XOR_WriteProcessMemory_22b9 {
  strings:
    $key_22b9 = { 75 cb [2] 47 e9 [2] 41 dc [2] 6f dc [2] 50 c0 }

  condition:
    any of them
}