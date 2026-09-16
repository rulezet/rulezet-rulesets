rule TTP_XOR_MULT_DOSStub_6072 {
  strings:
    $key_6072 = { 34 1a [2] 40 02 [2] 07 00 [2] 40 11 [2] 0e 1d [2] 02 17 [2] 15 1c [2] 0e 52 [2] 33 }

  condition:
    any of them
}