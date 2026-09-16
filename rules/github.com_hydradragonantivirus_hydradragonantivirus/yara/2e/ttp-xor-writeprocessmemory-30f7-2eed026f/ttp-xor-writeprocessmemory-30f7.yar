rule TTP_XOR_WriteProcessMemory_30f7 {
  strings:
    $key_30f7 = { 67 85 [2] 55 a7 [2] 53 92 [2] 7d 92 [2] 42 8e }

  condition:
    any of them
}