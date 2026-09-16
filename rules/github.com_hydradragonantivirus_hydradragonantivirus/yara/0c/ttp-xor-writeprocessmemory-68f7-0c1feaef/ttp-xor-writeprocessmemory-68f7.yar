rule TTP_XOR_WriteProcessMemory_68f7 {
  strings:
    $key_68f7 = { 3f 85 [2] 0d a7 [2] 0b 92 [2] 25 92 [2] 1a 8e }

  condition:
    any of them
}