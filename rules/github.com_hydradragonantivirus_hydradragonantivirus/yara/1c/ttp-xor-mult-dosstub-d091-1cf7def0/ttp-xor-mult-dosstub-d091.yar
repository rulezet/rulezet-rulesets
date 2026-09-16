rule TTP_XOR_MULT_DOSStub_d091 {
  strings:
    $key_d091 = { 84 f9 [2] f0 e1 [2] b7 e3 [2] f0 f2 [2] be fe [2] b2 f4 [2] a5 ff [2] be b1 [2] 83 }

  condition:
    any of them
}