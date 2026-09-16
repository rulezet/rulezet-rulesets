rule TTP_XOR_MULT_DOSStub_809d {
  strings:
    $key_809d = { d4 f5 [2] a0 ed [2] e7 ef [2] a0 fe [2] ee f2 [2] e2 f8 [2] f5 f3 [2] ee bd [2] d3 }

  condition:
    any of them
}