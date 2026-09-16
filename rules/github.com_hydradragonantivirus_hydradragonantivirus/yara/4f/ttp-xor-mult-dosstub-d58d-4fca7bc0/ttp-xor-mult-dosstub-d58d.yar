rule TTP_XOR_MULT_DOSStub_d58d {
  strings:
    $key_d58d = { 81 e5 [2] f5 fd [2] b2 ff [2] f5 ee [2] bb e2 [2] b7 e8 [2] a0 e3 [2] bb ad [2] 86 }

  condition:
    any of them
}