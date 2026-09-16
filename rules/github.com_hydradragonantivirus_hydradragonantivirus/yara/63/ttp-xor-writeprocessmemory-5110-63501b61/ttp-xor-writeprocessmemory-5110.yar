rule TTP_XOR_WriteProcessMemory_5110 {
  strings:
    $key_5110 = { 06 62 [2] 34 40 [2] 32 75 [2] 1c 75 [2] 23 69 }

  condition:
    any of them
}