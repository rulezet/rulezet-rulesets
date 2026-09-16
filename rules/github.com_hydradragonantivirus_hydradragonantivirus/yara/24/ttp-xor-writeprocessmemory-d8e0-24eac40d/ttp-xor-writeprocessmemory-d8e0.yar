rule TTP_XOR_WriteProcessMemory_d8e0 {
  strings:
    $key_d8e0 = { 8f 92 [2] bd b0 [2] bb 85 [2] 95 85 [2] aa 99 }

  condition:
    any of them
}