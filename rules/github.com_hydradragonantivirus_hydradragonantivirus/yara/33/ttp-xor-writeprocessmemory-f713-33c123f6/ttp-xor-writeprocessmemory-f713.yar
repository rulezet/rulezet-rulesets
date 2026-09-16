rule TTP_XOR_WriteProcessMemory_f713 {
  strings:
    $key_f713 = { a0 61 [2] 92 43 [2] 94 76 [2] ba 76 [2] 85 6a }

  condition:
    any of them
}