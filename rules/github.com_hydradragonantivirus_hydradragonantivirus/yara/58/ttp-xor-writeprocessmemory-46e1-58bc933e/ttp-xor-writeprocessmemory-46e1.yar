rule TTP_XOR_WriteProcessMemory_46e1 {
  strings:
    $key_46e1 = { 11 93 [2] 23 b1 [2] 25 84 [2] 0b 84 [2] 34 98 }

  condition:
    any of them
}