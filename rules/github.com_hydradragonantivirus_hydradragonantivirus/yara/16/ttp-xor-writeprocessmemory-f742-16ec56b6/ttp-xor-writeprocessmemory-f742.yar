rule TTP_XOR_WriteProcessMemory_f742 {
  strings:
    $key_f742 = { a0 30 [2] 92 12 [2] 94 27 [2] ba 27 [2] 85 3b }

  condition:
    any of them
}