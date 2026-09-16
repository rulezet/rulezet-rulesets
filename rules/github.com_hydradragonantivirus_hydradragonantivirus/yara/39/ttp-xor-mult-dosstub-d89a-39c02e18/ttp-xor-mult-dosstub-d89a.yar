rule TTP_XOR_MULT_DOSStub_d89a {
  strings:
    $key_d89a = { 8c f2 [2] f8 ea [2] bf e8 [2] f8 f9 [2] b6 f5 [2] ba ff [2] ad f4 [2] b6 ba [2] 8b }

  condition:
    any of them
}