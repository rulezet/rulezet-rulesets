rule TTP_XOR_MULT_DOSStub_d2ca {
  strings:
    $key_d2ca = { 86 a2 [2] f2 ba [2] b5 b8 [2] f2 a9 [2] bc a5 [2] b0 af [2] a7 a4 [2] bc ea [2] 81 }

  condition:
    any of them
}