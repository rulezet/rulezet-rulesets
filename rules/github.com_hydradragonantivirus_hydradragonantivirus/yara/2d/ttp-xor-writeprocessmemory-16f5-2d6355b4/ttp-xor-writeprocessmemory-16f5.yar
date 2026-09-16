rule TTP_XOR_WriteProcessMemory_16f5 {
  strings:
    $key_16f5 = { 41 87 [2] 73 a5 [2] 75 90 [2] 5b 90 [2] 64 8c }

  condition:
    any of them
}