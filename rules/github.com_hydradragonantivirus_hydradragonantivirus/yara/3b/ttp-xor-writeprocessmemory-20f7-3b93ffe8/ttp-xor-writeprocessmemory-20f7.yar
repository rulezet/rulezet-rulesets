rule TTP_XOR_WriteProcessMemory_20f7 {
  strings:
    $key_20f7 = { 77 85 [2] 45 a7 [2] 43 92 [2] 6d 92 [2] 52 8e }

  condition:
    any of them
}