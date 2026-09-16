rule TTP_XOR_MULT_DOSStub_ecd4 {
  strings:
    $key_ecd4 = { b8 bc [2] cc a4 [2] 8b a6 [2] cc b7 [2] 82 bb [2] 8e b1 [2] 99 ba [2] 82 f4 [2] bf }

  condition:
    any of them
}