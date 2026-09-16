rule TTP_XOR_WriteProcessMemory_2bf7 {
  strings:
    $key_2bf7 = { 7c 85 [2] 4e a7 [2] 48 92 [2] 66 92 [2] 59 8e }

  condition:
    any of them
}