rule TTP_XOR_MULT_DOSStub_d17f {
  strings:
    $key_d17f = { 85 17 [2] f1 0f [2] b6 0d [2] f1 1c [2] bf 10 [2] b3 1a [2] a4 11 [2] bf 5f [2] 82 }

  condition:
    any of them
}