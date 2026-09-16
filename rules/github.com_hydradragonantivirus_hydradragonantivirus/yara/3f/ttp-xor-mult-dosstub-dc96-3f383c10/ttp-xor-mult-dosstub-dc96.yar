rule TTP_XOR_MULT_DOSStub_dc96 {
  strings:
    $key_dc96 = { 88 fe [2] fc e6 [2] bb e4 [2] fc f5 [2] b2 f9 [2] be f3 [2] a9 f8 [2] b2 b6 [2] 8f }

  condition:
    any of them
}