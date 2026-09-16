rule TTP_XOR_MULT_DOSStub_d39d {
  strings:
    $key_d39d = { 87 f5 [2] f3 ed [2] b4 ef [2] f3 fe [2] bd f2 [2] b1 f8 [2] a6 f3 [2] bd bd [2] 80 }

  condition:
    any of them
}