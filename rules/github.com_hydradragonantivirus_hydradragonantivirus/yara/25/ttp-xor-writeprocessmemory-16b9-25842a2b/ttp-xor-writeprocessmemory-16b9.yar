rule TTP_XOR_WriteProcessMemory_16b9 {
  strings:
    $key_16b9 = { 41 cb [2] 73 e9 [2] 75 dc [2] 5b dc [2] 64 c0 }

  condition:
    any of them
}