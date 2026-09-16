rule TTP_XOR_MULT_DOSStub_d58f {
  strings:
    $key_d58f = { 81 e7 [2] f5 ff [2] b2 fd [2] f5 ec [2] bb e0 [2] b7 ea [2] a0 e1 [2] bb af [2] 86 }

  condition:
    any of them
}