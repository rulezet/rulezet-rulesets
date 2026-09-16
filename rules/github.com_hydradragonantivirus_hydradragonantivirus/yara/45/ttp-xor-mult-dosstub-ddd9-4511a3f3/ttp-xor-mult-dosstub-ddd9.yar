rule TTP_XOR_MULT_DOSStub_ddd9 {
  strings:
    $key_ddd9 = { 89 b1 [2] fd a9 [2] ba ab [2] fd ba [2] b3 b6 [2] bf bc [2] a8 b7 [2] b3 f9 [2] 8e }

  condition:
    any of them
}