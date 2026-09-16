rule TTP_XOR_MULT_DOSStub_859d {
  strings:
    $key_859d = { d1 f5 [2] a5 ed [2] e2 ef [2] a5 fe [2] eb f2 [2] e7 f8 [2] f0 f3 [2] eb bd [2] d6 }

  condition:
    any of them
}