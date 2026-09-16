rule TTP_XOR_MULT_DOSStub_dc98 {
  strings:
    $key_dc98 = { 88 f0 [2] fc e8 [2] bb ea [2] fc fb [2] b2 f7 [2] be fd [2] a9 f6 [2] b2 b8 [2] 8f }

  condition:
    any of them
}