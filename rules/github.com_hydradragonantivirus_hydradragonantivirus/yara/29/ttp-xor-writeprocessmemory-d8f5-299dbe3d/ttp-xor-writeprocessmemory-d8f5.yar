rule TTP_XOR_WriteProcessMemory_d8f5 {
  strings:
    $key_d8f5 = { 8f 87 [2] bd a5 [2] bb 90 [2] 95 90 [2] aa 8c }

  condition:
    any of them
}