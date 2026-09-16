rule TTP_XOR_WriteProcessMemory_51b9 {
  strings:
    $key_51b9 = { 06 cb [2] 34 e9 [2] 32 dc [2] 1c dc [2] 23 c0 }

  condition:
    any of them
}