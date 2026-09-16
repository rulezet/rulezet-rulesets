rule TTP_XOR_WriteProcessMemory_33f7 {
  strings:
    $key_33f7 = { 64 85 [2] 56 a7 [2] 50 92 [2] 7e 92 [2] 41 8e }

  condition:
    any of them
}