rule TTP_XOR_WriteProcessMemory_6ff7 {
  strings:
    $key_6ff7 = { 38 85 [2] 0a a7 [2] 0c 92 [2] 22 92 [2] 1d 8e }

  condition:
    any of them
}