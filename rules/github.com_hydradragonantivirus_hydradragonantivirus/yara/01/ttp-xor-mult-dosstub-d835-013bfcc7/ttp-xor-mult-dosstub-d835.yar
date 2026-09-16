rule TTP_XOR_MULT_DOSStub_d835 {
  strings:
    $key_d835 = { 8c 5d [2] f8 45 [2] bf 47 [2] f8 56 [2] b6 5a [2] ba 50 [2] ad 5b [2] b6 15 [2] 8b }

  condition:
    any of them
}