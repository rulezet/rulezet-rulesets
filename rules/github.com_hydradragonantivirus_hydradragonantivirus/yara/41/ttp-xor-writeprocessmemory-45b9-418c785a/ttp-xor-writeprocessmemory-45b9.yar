rule TTP_XOR_WriteProcessMemory_45b9 {
  strings:
    $key_45b9 = { 12 cb [2] 20 e9 [2] 26 dc [2] 08 dc [2] 37 c0 }

  condition:
    any of them
}