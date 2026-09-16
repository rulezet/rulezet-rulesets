rule TTP_XOR_WriteProcessMemory_f7e9 {
  strings:
    $key_f7e9 = { a0 9b [2] 92 b9 [2] 94 8c [2] ba 8c [2] 85 90 }

  condition:
    any of them
}