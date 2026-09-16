rule TTP_XOR_WriteProcessMemory_47f7 {
  strings:
    $key_47f7 = { 10 85 [2] 22 a7 [2] 24 92 [2] 0a 92 [2] 35 8e }

  condition:
    any of them
}