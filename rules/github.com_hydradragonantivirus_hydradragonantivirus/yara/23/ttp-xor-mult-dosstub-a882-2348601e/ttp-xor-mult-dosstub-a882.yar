rule TTP_XOR_MULT_DOSStub_a882 {
  strings:
    $key_a882 = { fc ea [2] 88 f2 [2] cf f0 [2] 88 e1 [2] c6 ed [2] ca e7 [2] dd ec [2] c6 a2 [2] fb }

  condition:
    any of them
}