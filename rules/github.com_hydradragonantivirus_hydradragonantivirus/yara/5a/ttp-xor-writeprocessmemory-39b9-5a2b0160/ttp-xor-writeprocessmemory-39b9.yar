rule TTP_XOR_WriteProcessMemory_39b9 {
  strings:
    $key_39b9 = { 6e cb [2] 5c e9 [2] 5a dc [2] 74 dc [2] 4b c0 }

  condition:
    any of them
}