rule TTP_XOR_MULT_DOSStub_7772 {
  strings:
    $key_7772 = { 23 1a [2] 57 02 [2] 10 00 [2] 57 11 [2] 19 1d [2] 15 17 [2] 02 1c [2] 19 52 [2] 24 }

  condition:
    any of them
}