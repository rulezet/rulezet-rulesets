rule TTP_XOR_MULT_DOSStub_d09a {
  strings:
    $key_d09a = { 84 f2 [2] f0 ea [2] b7 e8 [2] f0 f9 [2] be f5 [2] b2 ff [2] a5 f4 [2] be ba [2] 83 }

  condition:
    any of them
}