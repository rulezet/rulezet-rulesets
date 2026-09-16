rule TTP_XOR_WriteProcessMemory_5165 {
  strings:
    $key_5165 = { 06 17 [2] 34 35 [2] 32 00 [2] 1c 00 [2] 23 1c }

  condition:
    any of them
}