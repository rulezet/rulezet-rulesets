rule TTP_XOR_MULT_DOSStub_d883 {
  strings:
    $key_d883 = { 8c eb [2] f8 f3 [2] bf f1 [2] f8 e0 [2] b6 ec [2] ba e6 [2] ad ed [2] b6 a3 [2] 8b }

  condition:
    any of them
}