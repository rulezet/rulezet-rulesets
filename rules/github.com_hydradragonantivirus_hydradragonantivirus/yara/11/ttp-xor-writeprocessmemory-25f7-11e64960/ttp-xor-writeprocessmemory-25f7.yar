rule TTP_XOR_WriteProcessMemory_25f7 {
  strings:
    $key_25f7 = { 72 85 [2] 40 a7 [2] 46 92 [2] 68 92 [2] 57 8e }

  condition:
    any of them
}