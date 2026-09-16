rule TTP_XOR_MULT_DOSStub_ecd2 {
  strings:
    $key_ecd2 = { b8 ba [2] cc a2 [2] 8b a0 [2] cc b1 [2] 82 bd [2] 8e b7 [2] 99 bc [2] 82 f2 [2] bf }

  condition:
    any of them
}