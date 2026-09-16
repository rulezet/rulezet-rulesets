rule TTP_XOR_WriteProcessMemory_63e1 {
  strings:
    $key_63e1 = { 34 93 [2] 06 b1 [2] 00 84 [2] 2e 84 [2] 11 98 }

  condition:
    any of them
}