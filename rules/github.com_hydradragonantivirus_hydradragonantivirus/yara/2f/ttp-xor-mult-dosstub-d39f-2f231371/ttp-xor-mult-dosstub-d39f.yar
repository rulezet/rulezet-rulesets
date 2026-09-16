rule TTP_XOR_MULT_DOSStub_d39f {
  strings:
    $key_d39f = { 87 f7 [2] f3 ef [2] b4 ed [2] f3 fc [2] bd f0 [2] b1 fa [2] a6 f1 [2] bd bf [2] 80 }

  condition:
    any of them
}