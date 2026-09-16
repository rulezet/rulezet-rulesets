rule TTP_XOR_MULT_DOSStub_c372 {
  strings:
    $key_c372 = { 97 1a [2] e3 02 [2] a4 00 [2] e3 11 [2] ad 1d [2] a1 17 [2] b6 1c [2] ad 52 [2] 90 }

  condition:
    any of them
}