rule TTP_XOR_MULT_DOSStub_b075 {
  strings:
    $key_b075 = { e4 1d [2] 90 05 [2] d7 07 [2] 90 16 [2] de 1a [2] d2 10 [2] c5 1b [2] de 55 [2] e3 }

  condition:
    any of them
}