rule TTP_XOR_WriteProcessMemory_5107 {
  strings:
    $key_5107 = { 06 75 [2] 34 57 [2] 32 62 [2] 1c 62 [2] 23 7e }

  condition:
    any of them
}