rule TTP_XOR_WriteProcessMemory_1df7 {
  strings:
    $key_1df7 = { 4a 85 [2] 78 a7 [2] 7e 92 [2] 50 92 [2] 6f 8e }

  condition:
    any of them
}