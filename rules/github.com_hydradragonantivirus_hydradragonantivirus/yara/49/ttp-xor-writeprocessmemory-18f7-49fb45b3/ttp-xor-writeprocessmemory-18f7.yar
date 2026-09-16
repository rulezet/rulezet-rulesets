rule TTP_XOR_WriteProcessMemory_18f7 {
  strings:
    $key_18f7 = { 4f 85 [2] 7d a7 [2] 7b 92 [2] 55 92 [2] 6a 8e }

  condition:
    any of them
}