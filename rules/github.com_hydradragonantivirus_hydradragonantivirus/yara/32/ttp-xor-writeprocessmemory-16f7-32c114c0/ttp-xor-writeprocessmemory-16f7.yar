rule TTP_XOR_WriteProcessMemory_16f7 {
  strings:
    $key_16f7 = { 41 85 [2] 73 a7 [2] 75 92 [2] 5b 92 [2] 64 8e }

  condition:
    any of them
}