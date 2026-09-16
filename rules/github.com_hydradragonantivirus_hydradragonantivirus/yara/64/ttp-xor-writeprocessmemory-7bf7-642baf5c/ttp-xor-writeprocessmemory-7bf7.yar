rule TTP_XOR_WriteProcessMemory_7bf7 {
  strings:
    $key_7bf7 = { 2c 85 [2] 1e a7 [2] 18 92 [2] 36 92 [2] 09 8e }

  condition:
    any of them
}