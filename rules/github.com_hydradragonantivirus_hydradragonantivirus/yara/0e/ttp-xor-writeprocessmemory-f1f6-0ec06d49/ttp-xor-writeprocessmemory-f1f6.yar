rule TTP_XOR_WriteProcessMemory_f1f6 {
  strings:
    $key_f1f6 = { a6 84 [2] 94 a6 [2] 92 93 [2] bc 93 [2] 83 8f }

  condition:
    any of them
}