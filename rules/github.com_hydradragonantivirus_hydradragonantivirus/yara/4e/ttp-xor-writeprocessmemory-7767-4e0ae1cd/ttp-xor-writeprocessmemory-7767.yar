rule TTP_XOR_WriteProcessMemory_7767 {
  strings:
    $key_7767 = { 20 15 [2] 12 37 [2] 14 02 [2] 3a 02 [2] 05 1e }

  condition:
    any of them
}