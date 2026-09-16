rule TTP_XOR_WriteProcessMemory_c9e1 {
  strings:
    $key_c9e1 = { 9e 93 [2] ac b1 [2] aa 84 [2] 84 84 [2] bb 98 }

  condition:
    any of them
}