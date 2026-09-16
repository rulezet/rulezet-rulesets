rule TTP_XOR_MULT_DOSStub_d98d {
  strings:
    $key_d98d = { 8d e5 [2] f9 fd [2] be ff [2] f9 ee [2] b7 e2 [2] bb e8 [2] ac e3 [2] b7 ad [2] 8a }

  condition:
    any of them
}