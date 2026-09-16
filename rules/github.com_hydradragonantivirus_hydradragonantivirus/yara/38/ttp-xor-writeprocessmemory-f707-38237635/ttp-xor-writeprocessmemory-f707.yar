rule TTP_XOR_WriteProcessMemory_f707 {
  strings:
    $key_f707 = { a0 75 [2] 92 57 [2] 94 62 [2] ba 62 [2] 85 7e }

  condition:
    any of them
}