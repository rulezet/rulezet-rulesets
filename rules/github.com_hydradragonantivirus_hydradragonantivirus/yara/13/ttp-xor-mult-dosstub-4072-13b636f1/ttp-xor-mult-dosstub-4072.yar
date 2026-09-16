rule TTP_XOR_MULT_DOSStub_4072 {
  strings:
    $key_4072 = { 14 1a [2] 60 02 [2] 27 00 [2] 60 11 [2] 2e 1d [2] 22 17 [2] 35 1c [2] 2e 52 [2] 13 }

  condition:
    any of them
}