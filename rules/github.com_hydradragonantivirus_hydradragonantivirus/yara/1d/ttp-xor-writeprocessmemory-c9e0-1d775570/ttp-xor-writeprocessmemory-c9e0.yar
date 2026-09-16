rule TTP_XOR_WriteProcessMemory_c9e0 {
  strings:
    $key_c9e0 = { 9e 92 [2] ac b0 [2] aa 85 [2] 84 85 [2] bb 99 }

  condition:
    any of them
}