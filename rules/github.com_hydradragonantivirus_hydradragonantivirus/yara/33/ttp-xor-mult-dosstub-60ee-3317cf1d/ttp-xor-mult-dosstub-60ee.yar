rule TTP_XOR_MULT_DOSStub_60ee {
  strings:
    $key_60ee = { 34 86 [2] 40 9e [2] 07 9c [2] 40 8d [2] 0e 81 [2] 02 8b [2] 15 80 [2] 0e ce [2] 33 }

  condition:
    any of them
}