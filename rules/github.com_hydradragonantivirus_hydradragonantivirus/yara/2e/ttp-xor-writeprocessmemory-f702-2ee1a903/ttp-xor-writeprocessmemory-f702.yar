rule TTP_XOR_WriteProcessMemory_f702 {
  strings:
    $key_f702 = { a0 70 [2] 92 52 [2] 94 67 [2] ba 67 [2] 85 7b }

  condition:
    any of them
}