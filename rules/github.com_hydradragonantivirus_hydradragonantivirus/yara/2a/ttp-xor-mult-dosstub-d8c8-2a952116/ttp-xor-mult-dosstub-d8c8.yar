rule TTP_XOR_MULT_DOSStub_d8c8 {
  strings:
    $key_d8c8 = { 8c a0 [2] f8 b8 [2] bf ba [2] f8 ab [2] b6 a7 [2] ba ad [2] ad a6 [2] b6 e8 [2] 8b }

  condition:
    any of them
}