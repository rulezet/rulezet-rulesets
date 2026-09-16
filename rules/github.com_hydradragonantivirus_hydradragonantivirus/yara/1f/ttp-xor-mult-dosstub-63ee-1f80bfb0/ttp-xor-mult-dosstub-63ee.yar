rule TTP_XOR_MULT_DOSStub_63ee {
  strings:
    $key_63ee = { 37 86 [2] 43 9e [2] 04 9c [2] 43 8d [2] 0d 81 [2] 01 8b [2] 16 80 [2] 0d ce [2] 30 }

  condition:
    any of them
}