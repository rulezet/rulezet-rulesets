rule TTP_XOR_WriteProcessMemory_dec3 {
  strings:
    $key_dec3 = { 89 b1 [2] bb 93 [2] bd a6 [2] 93 a6 [2] ac ba }

  condition:
    any of them
}