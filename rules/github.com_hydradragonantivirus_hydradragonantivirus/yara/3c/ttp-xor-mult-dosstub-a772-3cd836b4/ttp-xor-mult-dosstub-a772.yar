rule TTP_XOR_MULT_DOSStub_a772 {
  strings:
    $key_a772 = { f3 1a [2] 87 02 [2] c0 00 [2] 87 11 [2] c9 1d [2] c5 17 [2] d2 1c [2] c9 52 [2] f4 }

  condition:
    any of them
}