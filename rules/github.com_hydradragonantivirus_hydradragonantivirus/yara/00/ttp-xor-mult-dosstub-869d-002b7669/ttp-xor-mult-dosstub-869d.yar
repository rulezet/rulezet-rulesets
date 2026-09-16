rule TTP_XOR_MULT_DOSStub_869d {
  strings:
    $key_869d = { d2 f5 [2] a6 ed [2] e1 ef [2] a6 fe [2] e8 f2 [2] e4 f8 [2] f3 f3 [2] e8 bd [2] d5 }

  condition:
    any of them
}