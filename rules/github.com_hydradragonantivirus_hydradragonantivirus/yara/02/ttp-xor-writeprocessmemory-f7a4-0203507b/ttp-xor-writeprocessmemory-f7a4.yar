rule TTP_XOR_WriteProcessMemory_f7a4 {
  strings:
    $key_f7a4 = { a0 d6 [2] 92 f4 [2] 94 c1 [2] ba c1 [2] 85 dd }

  condition:
    any of them
}