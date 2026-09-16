rule TTP_XOR_WriteProcessMemory_17b9 {
  strings:
    $key_17b9 = { 40 cb [2] 72 e9 [2] 74 dc [2] 5a dc [2] 65 c0 }

  condition:
    any of them
}