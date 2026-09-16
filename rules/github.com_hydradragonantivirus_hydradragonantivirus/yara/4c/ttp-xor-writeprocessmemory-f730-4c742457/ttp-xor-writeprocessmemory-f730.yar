rule TTP_XOR_WriteProcessMemory_f730 {
  strings:
    $key_f730 = { a0 42 [2] 92 60 [2] 94 55 [2] ba 55 [2] 85 49 }

  condition:
    any of them
}