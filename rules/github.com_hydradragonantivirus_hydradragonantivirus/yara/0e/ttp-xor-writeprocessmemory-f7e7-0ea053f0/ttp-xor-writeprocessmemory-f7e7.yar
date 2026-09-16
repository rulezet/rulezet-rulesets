rule TTP_XOR_WriteProcessMemory_f7e7 {
  strings:
    $key_f7e7 = { a0 95 [2] 92 b7 [2] 94 82 [2] ba 82 [2] 85 9e }

  condition:
    any of them
}