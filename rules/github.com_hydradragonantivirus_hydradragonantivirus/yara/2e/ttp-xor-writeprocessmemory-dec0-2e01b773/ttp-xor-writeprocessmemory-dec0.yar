rule TTP_XOR_WriteProcessMemory_dec0 {
  strings:
    $key_dec0 = { 89 b2 [2] bb 90 [2] bd a5 [2] 93 a5 [2] ac b9 }

  condition:
    any of them
}