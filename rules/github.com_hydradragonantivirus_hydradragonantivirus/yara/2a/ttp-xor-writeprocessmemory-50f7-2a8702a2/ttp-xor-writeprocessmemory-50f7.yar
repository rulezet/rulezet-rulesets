rule TTP_XOR_WriteProcessMemory_50f7 {
  strings:
    $key_50f7 = { 07 85 [2] 35 a7 [2] 33 92 [2] 1d 92 [2] 22 8e }

  condition:
    any of them
}