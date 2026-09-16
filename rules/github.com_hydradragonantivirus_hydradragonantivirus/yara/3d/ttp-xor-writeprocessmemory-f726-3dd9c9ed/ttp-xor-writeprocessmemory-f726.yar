rule TTP_XOR_WriteProcessMemory_f726 {
  strings:
    $key_f726 = { a0 54 [2] 92 76 [2] 94 43 [2] ba 43 [2] 85 5f }

  condition:
    any of them
}