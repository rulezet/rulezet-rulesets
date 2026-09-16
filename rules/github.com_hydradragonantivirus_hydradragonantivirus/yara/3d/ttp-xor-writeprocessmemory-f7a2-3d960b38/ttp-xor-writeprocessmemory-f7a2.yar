rule TTP_XOR_WriteProcessMemory_f7a2 {
  strings:
    $key_f7a2 = { a0 d0 [2] 92 f2 [2] 94 c7 [2] ba c7 [2] 85 db }

  condition:
    any of them
}