rule TTP_XOR_WriteProcessMemory_c9b1 {
  strings:
    $key_c9b1 = { 9e c3 [2] ac e1 [2] aa d4 [2] 84 d4 [2] bb c8 }

  condition:
    any of them
}