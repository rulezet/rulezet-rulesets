rule TTP_XOR_WriteProcessMemory_06b9 {
  strings:
    $key_06b9 = { 51 cb [2] 63 e9 [2] 65 dc [2] 4b dc [2] 74 c0 }

  condition:
    any of them
}