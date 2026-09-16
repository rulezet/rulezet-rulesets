rule TTP_XOR_WriteProcessMemory_cdb4 {
  strings:
    $key_cdb4 = { 9a c6 [2] a8 e4 [2] ae d1 [2] 80 d1 [2] bf cd }

  condition:
    any of them
}