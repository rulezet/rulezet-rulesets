rule TTP_XOR_WriteProcessMemory_76e7 {
  strings:
    $key_76e7 = { 21 95 [2] 13 b7 [2] 15 82 [2] 3b 82 [2] 04 9e }

  condition:
    any of them
}