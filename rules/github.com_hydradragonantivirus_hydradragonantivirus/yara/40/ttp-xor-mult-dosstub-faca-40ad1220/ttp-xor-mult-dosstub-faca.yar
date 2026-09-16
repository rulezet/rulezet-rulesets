rule TTP_XOR_MULT_DOSStub_faca {
  strings:
    $key_faca = { ae a2 [2] da ba [2] 9d b8 [2] da a9 [2] 94 a5 [2] 98 af [2] 8f a4 [2] 94 ea [2] a9 }

  condition:
    any of them
}