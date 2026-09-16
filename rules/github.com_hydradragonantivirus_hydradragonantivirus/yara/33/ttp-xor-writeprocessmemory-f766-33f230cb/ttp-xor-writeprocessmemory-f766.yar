rule TTP_XOR_WriteProcessMemory_f766 {
  strings:
    $key_f766 = { a0 14 [2] 92 36 [2] 94 03 [2] ba 03 [2] 85 1f }

  condition:
    any of them
}