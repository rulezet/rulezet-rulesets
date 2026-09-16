rule TTP_XOR_WriteProcessMemory_73b9 {
  strings:
    $key_73b9 = { 24 cb [2] 16 e9 [2] 10 dc [2] 3e dc [2] 01 c0 }

  condition:
    any of them
}