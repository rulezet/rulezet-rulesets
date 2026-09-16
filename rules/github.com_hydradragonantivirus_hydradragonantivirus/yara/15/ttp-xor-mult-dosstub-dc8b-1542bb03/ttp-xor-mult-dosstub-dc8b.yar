rule TTP_XOR_MULT_DOSStub_dc8b {
  strings:
    $key_dc8b = { 88 e3 [2] fc fb [2] bb f9 [2] fc e8 [2] b2 e4 [2] be ee [2] a9 e5 [2] b2 ab [2] 8f }

  condition:
    any of them
}