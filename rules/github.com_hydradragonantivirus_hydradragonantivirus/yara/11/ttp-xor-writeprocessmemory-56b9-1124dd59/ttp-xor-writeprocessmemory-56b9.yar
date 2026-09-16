rule TTP_XOR_WriteProcessMemory_56b9 {
  strings:
    $key_56b9 = { 01 cb [2] 33 e9 [2] 35 dc [2] 1b dc [2] 24 c0 }

  condition:
    any of them
}