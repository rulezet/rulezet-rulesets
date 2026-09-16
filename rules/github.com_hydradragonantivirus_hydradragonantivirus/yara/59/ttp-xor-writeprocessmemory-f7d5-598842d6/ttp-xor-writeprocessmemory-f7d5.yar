rule TTP_XOR_WriteProcessMemory_f7d5 {
  strings:
    $key_f7d5 = { a0 a7 [2] 92 85 [2] 94 b0 [2] ba b0 [2] 85 ac }

  condition:
    any of them
}