rule TTP_XOR_MULT_DOSStub_dc87 {
  strings:
    $key_dc87 = { 88 ef [2] fc f7 [2] bb f5 [2] fc e4 [2] b2 e8 [2] be e2 [2] a9 e9 [2] b2 a7 [2] 8f }

  condition:
    any of them
}