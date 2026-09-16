rule TTP_XOR_WriteProcessMemory_65f7 {
  strings:
    $key_65f7 = { 32 85 [2] 00 a7 [2] 06 92 [2] 28 92 [2] 17 8e }

  condition:
    any of them
}