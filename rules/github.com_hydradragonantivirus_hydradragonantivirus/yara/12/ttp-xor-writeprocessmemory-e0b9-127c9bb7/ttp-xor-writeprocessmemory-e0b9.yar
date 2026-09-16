rule TTP_XOR_WriteProcessMemory_e0b9 {
  strings:
    $key_e0b9 = { b7 cb [2] 85 e9 [2] 83 dc [2] ad dc [2] 92 c0 }

  condition:
    any of them
}