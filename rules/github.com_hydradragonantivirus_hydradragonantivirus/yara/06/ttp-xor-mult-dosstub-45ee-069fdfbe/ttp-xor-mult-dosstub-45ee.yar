rule TTP_XOR_MULT_DOSStub_45ee {
  strings:
    $key_45ee = { 11 86 [2] 65 9e [2] 22 9c [2] 65 8d [2] 2b 81 [2] 27 8b [2] 30 80 [2] 2b ce [2] 16 }

  condition:
    any of them
}