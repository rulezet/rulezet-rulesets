rule TTP_XOR_WriteProcessMemory_44e7 {
  strings:
    $key_44e7 = { 13 95 [2] 21 b7 [2] 27 82 [2] 09 82 [2] 36 9e }

  condition:
    any of them
}