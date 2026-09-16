rule TTP_XOR_MULT_DOSStub_b076 {
  strings:
    $key_b076 = { e4 1e [2] 90 06 [2] d7 04 [2] 90 15 [2] de 19 [2] d2 13 [2] c5 18 [2] de 56 [2] e3 }

  condition:
    any of them
}