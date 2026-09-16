rule TTP_XOR_WriteProcessMemory_73f7 {
  strings:
    $key_73f7 = { 24 85 [2] 16 a7 [2] 10 92 [2] 3e 92 [2] 01 8e }

  condition:
    any of them
}