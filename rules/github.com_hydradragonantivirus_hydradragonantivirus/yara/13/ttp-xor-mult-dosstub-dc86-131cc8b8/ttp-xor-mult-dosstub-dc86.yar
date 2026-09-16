rule TTP_XOR_MULT_DOSStub_dc86 {
  strings:
    $key_dc86 = { 88 ee [2] fc f6 [2] bb f4 [2] fc e5 [2] b2 e9 [2] be e3 [2] a9 e8 [2] b2 a6 [2] 8f }

  condition:
    any of them
}