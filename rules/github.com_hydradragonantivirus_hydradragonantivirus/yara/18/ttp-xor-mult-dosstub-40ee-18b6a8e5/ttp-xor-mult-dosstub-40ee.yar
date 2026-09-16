rule TTP_XOR_MULT_DOSStub_40ee {
  strings:
    $key_40ee = { 14 86 [2] 60 9e [2] 27 9c [2] 60 8d [2] 2e 81 [2] 22 8b [2] 35 80 [2] 2e ce [2] 13 }

  condition:
    any of them
}