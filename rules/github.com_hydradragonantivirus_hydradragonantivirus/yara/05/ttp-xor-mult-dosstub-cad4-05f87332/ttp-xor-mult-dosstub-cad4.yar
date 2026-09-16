rule TTP_XOR_MULT_DOSStub_cad4 {
  strings:
    $key_cad4 = { 9e bc [2] ea a4 [2] ad a6 [2] ea b7 [2] a4 bb [2] a8 b1 [2] bf ba [2] a4 f4 [2] 99 }

  condition:
    any of them
}