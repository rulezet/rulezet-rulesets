rule TTP_XOR_WriteProcessMemory_34b9 {
  strings:
    $key_34b9 = { 63 cb [2] 51 e9 [2] 57 dc [2] 79 dc [2] 46 c0 }

  condition:
    any of them
}