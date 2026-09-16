rule TTP_XOR_WriteProcessMemory_77e7 {
  strings:
    $key_77e7 = { 20 95 [2] 12 b7 [2] 14 82 [2] 3a 82 [2] 05 9e }

  condition:
    any of them
}