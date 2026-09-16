rule TTP_XOR_WriteProcessMemory_d8f7 {
  strings:
    $key_d8f7 = { 8f 85 [2] bd a7 [2] bb 92 [2] 95 92 [2] aa 8e }

  condition:
    any of them
}