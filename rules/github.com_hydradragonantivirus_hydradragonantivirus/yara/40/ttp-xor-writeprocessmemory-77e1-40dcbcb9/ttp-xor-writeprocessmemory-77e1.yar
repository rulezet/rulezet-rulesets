rule TTP_XOR_WriteProcessMemory_77e1 {
  strings:
    $key_77e1 = { 20 93 [2] 12 b1 [2] 14 84 [2] 3a 84 [2] 05 98 }

  condition:
    any of them
}