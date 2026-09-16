rule TTP_XOR_MULT_DOSStub_d38f {
  strings:
    $key_d38f = { 87 e7 [2] f3 ff [2] b4 fd [2] f3 ec [2] bd e0 [2] b1 ea [2] a6 e1 [2] bd af [2] 80 }

  condition:
    any of them
}