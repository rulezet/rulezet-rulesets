rule TTP_XOR_WriteProcessMemory_5df7 {
  strings:
    $key_5df7 = { 0a 85 [2] 38 a7 [2] 3e 92 [2] 10 92 [2] 2f 8e }

  condition:
    any of them
}