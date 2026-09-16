rule TTP_XOR_MULT_DOSStub_dcd2 {
  strings:
    $key_dcd2 = { 88 ba [2] fc a2 [2] bb a0 [2] fc b1 [2] b2 bd [2] be b7 [2] a9 bc [2] b2 f2 [2] 8f }

  condition:
    any of them
}