rule TTP_XOR_WriteProcessMemory_04b9 {
  strings:
    $key_04b9 = { 53 cb [2] 61 e9 [2] 67 dc [2] 49 dc [2] 76 c0 }

  condition:
    any of them
}