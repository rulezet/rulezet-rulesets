rule TTP_XOR_WriteProcessMemory_78f7 {
  strings:
    $key_78f7 = { 2f 85 [2] 1d a7 [2] 1b 92 [2] 35 92 [2] 0a 8e }

  condition:
    any of them
}