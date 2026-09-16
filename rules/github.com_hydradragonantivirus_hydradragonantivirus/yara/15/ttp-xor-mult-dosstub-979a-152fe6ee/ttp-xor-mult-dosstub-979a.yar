rule TTP_XOR_MULT_DOSStub_979a {
  strings:
    $key_979a = { c3 f2 [2] b7 ea [2] f0 e8 [2] b7 f9 [2] f9 f5 [2] f5 ff [2] e2 f4 [2] f9 ba [2] c4 }

  condition:
    any of them
}