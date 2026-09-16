rule TTP_XOR_WriteProcessMemory_cdb1 {
  strings:
    $key_cdb1 = { 9a c3 [2] a8 e1 [2] ae d4 [2] 80 d4 [2] bf c8 }

  condition:
    any of them
}