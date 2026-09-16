rule TTP_XOR_WriteProcessMemory_f7e2 {
  strings:
    $key_f7e2 = { a0 90 [2] 92 b2 [2] 94 87 [2] ba 87 [2] 85 9b }

  condition:
    any of them
}