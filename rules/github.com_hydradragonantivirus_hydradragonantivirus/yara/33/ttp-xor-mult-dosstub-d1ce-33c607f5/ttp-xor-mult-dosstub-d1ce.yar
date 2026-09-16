rule TTP_XOR_MULT_DOSStub_d1ce {
  strings:
    $key_d1ce = { 85 a6 [2] f1 be [2] b6 bc [2] f1 ad [2] bf a1 [2] b3 ab [2] a4 a0 [2] bf ee [2] 82 }

  condition:
    any of them
}