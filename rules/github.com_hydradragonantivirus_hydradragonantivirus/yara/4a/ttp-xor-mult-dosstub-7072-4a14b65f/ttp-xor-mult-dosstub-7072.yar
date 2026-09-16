rule TTP_XOR_MULT_DOSStub_7072 {
  strings:
    $key_7072 = { 24 1a [2] 50 02 [2] 17 00 [2] 50 11 [2] 1e 1d [2] 12 17 [2] 05 1c [2] 1e 52 [2] 23 }

  condition:
    any of them
}