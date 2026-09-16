rule TTP_XOR_WriteProcessMemory_c9b9 {
  strings:
    $key_c9b9 = { 9e cb [2] ac e9 [2] aa dc [2] 84 dc [2] bb c0 }

  condition:
    any of them
}