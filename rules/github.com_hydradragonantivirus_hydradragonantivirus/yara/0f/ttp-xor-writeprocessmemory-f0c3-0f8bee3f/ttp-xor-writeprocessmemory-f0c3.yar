rule TTP_XOR_WriteProcessMemory_f0c3 {
  strings:
    $key_f0c3 = { a7 b1 [2] 95 93 [2] 93 a6 [2] bd a6 [2] 82 ba }

  condition:
    any of them
}