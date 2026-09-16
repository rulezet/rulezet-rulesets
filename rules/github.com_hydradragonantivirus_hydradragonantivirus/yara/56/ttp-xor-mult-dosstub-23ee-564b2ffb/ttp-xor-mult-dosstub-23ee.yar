rule TTP_XOR_MULT_DOSStub_23ee {
  strings:
    $key_23ee = { 77 86 [2] 03 9e [2] 44 9c [2] 03 8d [2] 4d 81 [2] 41 8b [2] 56 80 [2] 4d ce [2] 70 }

  condition:
    any of them
}