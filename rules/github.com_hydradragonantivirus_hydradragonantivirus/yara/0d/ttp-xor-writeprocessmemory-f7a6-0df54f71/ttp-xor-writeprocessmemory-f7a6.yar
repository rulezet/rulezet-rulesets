rule TTP_XOR_WriteProcessMemory_f7a6 {
  strings:
    $key_f7a6 = { a0 d4 [2] 92 f6 [2] 94 c3 [2] ba c3 [2] 85 df }

  condition:
    any of them
}