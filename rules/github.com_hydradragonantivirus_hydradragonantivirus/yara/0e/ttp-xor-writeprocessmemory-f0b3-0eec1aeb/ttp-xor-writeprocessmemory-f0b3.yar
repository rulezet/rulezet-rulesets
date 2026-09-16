rule TTP_XOR_WriteProcessMemory_f0b3 {
  strings:
    $key_f0b3 = { a7 c1 [2] 95 e3 [2] 93 d6 [2] bd d6 [2] 82 ca }

  condition:
    any of them
}