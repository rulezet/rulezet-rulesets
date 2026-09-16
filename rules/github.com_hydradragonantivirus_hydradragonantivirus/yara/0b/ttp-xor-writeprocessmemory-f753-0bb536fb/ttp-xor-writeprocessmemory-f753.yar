rule TTP_XOR_WriteProcessMemory_f753 {
  strings:
    $key_f753 = { a0 21 [2] 92 03 [2] 94 36 [2] ba 36 [2] 85 2a }

  condition:
    any of them
}