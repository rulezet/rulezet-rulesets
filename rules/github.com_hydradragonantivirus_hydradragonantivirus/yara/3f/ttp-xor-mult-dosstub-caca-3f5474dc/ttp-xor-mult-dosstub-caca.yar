rule TTP_XOR_MULT_DOSStub_caca {
  strings:
    $key_caca = { 9e a2 [2] ea ba [2] ad b8 [2] ea a9 [2] a4 a5 [2] a8 af [2] bf a4 [2] a4 ea [2] 99 }

  condition:
    any of them
}