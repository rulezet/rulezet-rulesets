rule TTP_XOR_WriteProcessMemory_f7f9 {
  strings:
    $key_f7f9 = { a0 8b [2] 92 a9 [2] 94 9c [2] ba 9c [2] 85 80 }

  condition:
    any of them
}