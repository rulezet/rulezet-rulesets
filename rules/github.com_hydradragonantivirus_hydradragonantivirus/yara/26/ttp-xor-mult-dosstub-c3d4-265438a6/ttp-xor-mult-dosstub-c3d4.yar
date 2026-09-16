rule TTP_XOR_MULT_DOSStub_c3d4 {
  strings:
    $key_c3d4 = { 97 bc [2] e3 a4 [2] a4 a6 [2] e3 b7 [2] ad bb [2] a1 b1 [2] b6 ba [2] ad f4 [2] 90 }

  condition:
    any of them
}