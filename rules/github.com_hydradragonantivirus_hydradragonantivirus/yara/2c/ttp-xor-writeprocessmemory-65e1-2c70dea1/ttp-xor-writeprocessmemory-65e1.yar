rule TTP_XOR_WriteProcessMemory_65e1 {
  strings:
    $key_65e1 = { 32 93 [2] 00 b1 [2] 06 84 [2] 28 84 [2] 17 98 }

  condition:
    any of them
}