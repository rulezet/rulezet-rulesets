rule TTP_XOR_WriteProcessMemory_65e7 {
  strings:
    $key_65e7 = { 32 95 [2] 00 b7 [2] 06 82 [2] 28 82 [2] 17 9e }

  condition:
    any of them
}