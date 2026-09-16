rule TTP_XOR_MULT_DOSStub_d8d3 {
  strings:
    $key_d8d3 = { 8c bb [2] f8 a3 [2] bf a1 [2] f8 b0 [2] b6 bc [2] ba b6 [2] ad bd [2] b6 f3 [2] 8b }

  condition:
    any of them
}