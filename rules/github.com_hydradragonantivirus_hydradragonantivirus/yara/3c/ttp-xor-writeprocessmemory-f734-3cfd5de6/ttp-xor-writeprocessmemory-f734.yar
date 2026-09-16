rule TTP_XOR_WriteProcessMemory_f734 {
  strings:
    $key_f734 = { a0 46 [2] 92 64 [2] 94 51 [2] ba 51 [2] 85 4d }

  condition:
    any of them
}