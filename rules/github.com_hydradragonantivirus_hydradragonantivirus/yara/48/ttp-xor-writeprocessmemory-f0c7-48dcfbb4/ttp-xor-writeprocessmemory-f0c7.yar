rule TTP_XOR_WriteProcessMemory_f0c7 {
  strings:
    $key_f0c7 = { a7 b5 [2] 95 97 [2] 93 a2 [2] bd a2 [2] 82 be }

  condition:
    any of them
}