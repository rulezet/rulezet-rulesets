rule TTP_XOR_MULT_DOSStub_ca9d {
  strings:
    $key_ca9d = { 9e f5 [2] ea ed [2] ad ef [2] ea fe [2] a4 f2 [2] a8 f8 [2] bf f3 [2] a4 bd [2] 99 }

  condition:
    any of them
}