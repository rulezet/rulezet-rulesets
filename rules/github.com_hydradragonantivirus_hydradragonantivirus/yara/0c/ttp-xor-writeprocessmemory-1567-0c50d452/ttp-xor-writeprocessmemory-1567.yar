rule TTP_XOR_WriteProcessMemory_1567 {
  strings:
    $key_1567 = { 42 15 [2] 70 37 [2] 76 02 [2] 58 02 [2] 67 1e }

  condition:
    any of them
}