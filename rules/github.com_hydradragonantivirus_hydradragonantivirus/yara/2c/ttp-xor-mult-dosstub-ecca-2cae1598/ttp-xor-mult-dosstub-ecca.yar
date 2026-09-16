rule TTP_XOR_MULT_DOSStub_ecca {
  strings:
    $key_ecca = { b8 a2 [2] cc ba [2] 8b b8 [2] cc a9 [2] 82 a5 [2] 8e af [2] 99 a4 [2] 82 ea [2] bf }

  condition:
    any of them
}