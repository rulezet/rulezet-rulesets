rule TTP_XOR_MULT_DOSStub_dc84 {
  strings:
    $key_dc84 = { 88 ec [2] fc f4 [2] bb f6 [2] fc e7 [2] b2 eb [2] be e1 [2] a9 ea [2] b2 a4 [2] 8f }

  condition:
    any of them
}