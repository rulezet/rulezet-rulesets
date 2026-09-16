rule TTP_XOR_MULT_DOSStub_919d {
  strings:
    $key_919d = { c5 f5 [2] b1 ed [2] f6 ef [2] b1 fe [2] ff f2 [2] f3 f8 [2] e4 f3 [2] ff bd [2] c2 }

  condition:
    any of them
}