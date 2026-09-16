rule TTP_XOR_WriteProcessMemory_47e1 {
  strings:
    $key_47e1 = { 10 93 [2] 22 b1 [2] 24 84 [2] 0a 84 [2] 35 98 }

  condition:
    any of them
}