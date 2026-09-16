rule TTP_XOR_WriteProcessMemory_f779 {
  strings:
    $key_f779 = { a0 0b [2] 92 29 [2] 94 1c [2] ba 1c [2] 85 00 }

  condition:
    any of them
}