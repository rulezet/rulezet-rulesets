rule TTP_XOR_MULT_DOSStub_d81f {
  strings:
    $key_d81f = { 8c 77 [2] f8 6f [2] bf 6d [2] f8 7c [2] b6 70 [2] ba 7a [2] ad 71 [2] b6 3f [2] 8b }

  condition:
    any of them
}