rule TTP_XOR_WriteProcessMemory_f7f4 {
  strings:
    $key_f7f4 = { a0 86 [2] 92 a4 [2] 94 91 [2] ba 91 [2] 85 8d }

  condition:
    any of them
}