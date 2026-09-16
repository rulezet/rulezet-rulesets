rule TTP_XOR_WriteProcessMemory_75f7 {
  strings:
    $key_75f7 = { 22 85 [2] 10 a7 [2] 16 92 [2] 38 92 [2] 07 8e }

  condition:
    any of them
}