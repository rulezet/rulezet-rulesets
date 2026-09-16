rule TTP_XOR_WriteProcessMemory_73f5 {
  strings:
    $key_73f5 = { 24 87 [2] 16 a5 [2] 10 90 [2] 3e 90 [2] 01 8c }

  condition:
    any of them
}