rule TTP_XOR_WriteProcessMemory_26b9 {
  strings:
    $key_26b9 = { 71 cb [2] 43 e9 [2] 45 dc [2] 6b dc [2] 54 c0 }

  condition:
    any of them
}