rule TTP_XOR_MULT_DOSStub_1072 {
  strings:
    $key_1072 = { 44 1a [2] 30 02 [2] 77 00 [2] 30 11 [2] 7e 1d [2] 72 17 [2] 65 1c [2] 7e 52 [2] 43 }

  condition:
    any of them
}