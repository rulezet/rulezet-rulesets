rule TTP_XOR_WriteProcessMemory_11f7 {
  strings:
    $key_11f7 = { 46 85 [2] 74 a7 [2] 72 92 [2] 5c 92 [2] 63 8e }

  condition:
    any of them
}