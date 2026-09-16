rule TTP_XOR_WriteProcessMemory_f747 {
  strings:
    $key_f747 = { a0 35 [2] 92 17 [2] 94 22 [2] ba 22 [2] 85 3e }

  condition:
    any of them
}