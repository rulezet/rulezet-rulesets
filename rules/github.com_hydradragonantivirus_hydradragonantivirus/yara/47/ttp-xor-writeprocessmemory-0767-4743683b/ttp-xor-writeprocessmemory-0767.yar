rule TTP_XOR_WriteProcessMemory_0767 {
  strings:
    $key_0767 = { 50 15 [2] 62 37 [2] 64 02 [2] 4a 02 [2] 75 1e }

  condition:
    any of them
}