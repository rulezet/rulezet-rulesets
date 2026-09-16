rule TTP_XOR_MULT_DOSStub_928d {
  strings:
    $key_928d = { c6 e5 [2] b2 fd [2] f5 ff [2] b2 ee [2] fc e2 [2] f0 e8 [2] e7 e3 [2] fc ad [2] c1 }

  condition:
    any of them
}