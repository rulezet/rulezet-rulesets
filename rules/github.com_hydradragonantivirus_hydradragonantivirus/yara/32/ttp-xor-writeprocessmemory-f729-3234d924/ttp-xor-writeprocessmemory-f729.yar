rule TTP_XOR_WriteProcessMemory_f729 {
  strings:
    $key_f729 = { a0 5b [2] 92 79 [2] 94 4c [2] ba 4c [2] 85 50 }

  condition:
    any of them
}