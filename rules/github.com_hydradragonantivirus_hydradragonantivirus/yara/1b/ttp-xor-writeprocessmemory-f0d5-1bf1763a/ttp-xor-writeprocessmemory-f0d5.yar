rule TTP_XOR_WriteProcessMemory_f0d5 {
  strings:
    $key_f0d5 = { a7 a7 [2] 95 85 [2] 93 b0 [2] bd b0 [2] 82 ac }

  condition:
    any of them
}