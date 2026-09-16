rule TTP_XOR_WriteProcessMemory_7757 {
  strings:
    $key_7757 = { 20 25 [2] 12 07 [2] 14 32 [2] 3a 32 [2] 05 2e }

  condition:
    any of them
}