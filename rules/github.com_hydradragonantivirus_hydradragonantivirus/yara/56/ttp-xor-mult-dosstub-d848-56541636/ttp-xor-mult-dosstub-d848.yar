rule TTP_XOR_MULT_DOSStub_d848 {
  strings:
    $key_d848 = { 8c 20 [2] f8 38 [2] bf 3a [2] f8 2b [2] b6 27 [2] ba 2d [2] ad 26 [2] b6 68 [2] 8b }

  condition:
    any of them
}