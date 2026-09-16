rule TTP_XOR_WriteProcessMemory_56f7 {
  strings:
    $key_56f7 = { 01 85 [2] 33 a7 [2] 35 92 [2] 1b 92 [2] 24 8e }

  condition:
    any of them
}