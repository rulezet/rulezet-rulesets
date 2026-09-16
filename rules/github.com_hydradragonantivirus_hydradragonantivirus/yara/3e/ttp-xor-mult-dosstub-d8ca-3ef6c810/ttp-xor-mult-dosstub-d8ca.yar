rule TTP_XOR_MULT_DOSStub_d8ca {
  strings:
    $key_d8ca = { 8c a2 [2] f8 ba [2] bf b8 [2] f8 a9 [2] b6 a5 [2] ba af [2] ad a4 [2] b6 ea [2] 8b }

  condition:
    any of them
}