rule TTP_XOR_MULT_DOSStub_a49d {
  strings:
    $key_a49d = { f0 f5 [2] 84 ed [2] c3 ef [2] 84 fe [2] ca f2 [2] c6 f8 [2] d1 f3 [2] ca bd [2] f7 }

  condition:
    any of them
}