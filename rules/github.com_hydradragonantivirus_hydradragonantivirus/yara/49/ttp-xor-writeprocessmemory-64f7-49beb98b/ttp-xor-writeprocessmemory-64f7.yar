rule TTP_XOR_WriteProcessMemory_64f7 {
  strings:
    $key_64f7 = { 33 85 [2] 01 a7 [2] 07 92 [2] 29 92 [2] 16 8e }

  condition:
    any of them
}