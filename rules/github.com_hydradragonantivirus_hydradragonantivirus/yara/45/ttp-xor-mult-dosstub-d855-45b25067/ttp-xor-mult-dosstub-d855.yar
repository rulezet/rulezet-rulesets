rule TTP_XOR_MULT_DOSStub_d855 {
  strings:
    $key_d855 = { 8c 3d [2] f8 25 [2] bf 27 [2] f8 36 [2] b6 3a [2] ba 30 [2] ad 3b [2] b6 75 [2] 8b }

  condition:
    any of them
}