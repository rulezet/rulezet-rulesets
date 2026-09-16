rule TTP_XOR_WriteProcessMemory_f735 {
  strings:
    $key_f735 = { a0 47 [2] 92 65 [2] 94 50 [2] ba 50 [2] 85 4c }

  condition:
    any of them
}