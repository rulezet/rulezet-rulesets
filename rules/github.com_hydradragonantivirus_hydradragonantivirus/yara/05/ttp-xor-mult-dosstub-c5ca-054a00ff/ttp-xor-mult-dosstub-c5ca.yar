rule TTP_XOR_MULT_DOSStub_c5ca {
  strings:
    $key_c5ca = { 91 a2 [2] e5 ba [2] a2 b8 [2] e5 a9 [2] ab a5 [2] a7 af [2] b0 a4 [2] ab ea [2] 96 }

  condition:
    any of them
}