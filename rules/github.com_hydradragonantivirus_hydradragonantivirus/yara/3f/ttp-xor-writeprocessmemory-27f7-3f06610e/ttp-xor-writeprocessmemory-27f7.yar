rule TTP_XOR_WriteProcessMemory_27f7 {
  strings:
    $key_27f7 = { 70 85 [2] 42 a7 [2] 44 92 [2] 6a 92 [2] 55 8e }

  condition:
    any of them
}