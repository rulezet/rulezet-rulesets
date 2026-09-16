rule TTP_XOR_WriteProcessMemory_5115 {
  strings:
    $key_5115 = { 06 67 [2] 34 45 [2] 32 70 [2] 1c 70 [2] 23 6c }

  condition:
    any of them
}