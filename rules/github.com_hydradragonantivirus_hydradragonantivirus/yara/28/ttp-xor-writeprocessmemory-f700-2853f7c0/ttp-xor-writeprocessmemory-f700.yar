rule TTP_XOR_WriteProcessMemory_f700 {
  strings:
    $key_f700 = { a0 72 [2] 92 50 [2] 94 65 [2] ba 65 [2] 85 79 }

  condition:
    any of them
}