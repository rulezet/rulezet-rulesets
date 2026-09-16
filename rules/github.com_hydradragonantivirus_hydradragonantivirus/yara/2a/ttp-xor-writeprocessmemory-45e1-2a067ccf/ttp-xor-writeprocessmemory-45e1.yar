rule TTP_XOR_WriteProcessMemory_45e1 {
  strings:
    $key_45e1 = { 12 93 [2] 20 b1 [2] 26 84 [2] 08 84 [2] 37 98 }

  condition:
    any of them
}