rule TTP_XOR_WriteProcessMemory_f740 {
  strings:
    $key_f740 = { a0 32 [2] 92 10 [2] 94 25 [2] ba 25 [2] 85 39 }

  condition:
    any of them
}