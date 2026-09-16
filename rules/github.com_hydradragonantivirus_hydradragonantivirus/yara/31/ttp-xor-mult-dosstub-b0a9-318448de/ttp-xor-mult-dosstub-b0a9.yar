rule TTP_XOR_MULT_DOSStub_b0a9 {
  strings:
    $key_b0a9 = { e4 c1 [2] 90 d9 [2] d7 db [2] 90 ca [2] de c6 [2] d2 cc [2] c5 c7 [2] de 89 [2] e3 }

  condition:
    any of them
}