rule TTP_XOR_WriteProcessMemory_5ff7 {
  strings:
    $key_5ff7 = { 08 85 [2] 3a a7 [2] 3c 92 [2] 12 92 [2] 2d 8e }

  condition:
    any of them
}