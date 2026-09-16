rule TTP_XOR_WriteProcessMemory_72b9 {
  strings:
    $key_72b9 = { 25 cb [2] 17 e9 [2] 11 dc [2] 3f dc [2] 00 c0 }

  condition:
    any of them
}