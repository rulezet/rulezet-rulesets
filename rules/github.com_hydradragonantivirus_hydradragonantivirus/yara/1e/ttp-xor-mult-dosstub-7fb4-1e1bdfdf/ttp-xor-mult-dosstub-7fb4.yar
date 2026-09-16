rule TTP_XOR_MULT_DOSStub_7fb4 {
  strings:
    $key_7fb4 = { 2b dc [2] 5f c4 [2] 18 c6 [2] 5f d7 [2] 11 db [2] 1d d1 [2] 0a da [2] 11 94 [2] 2c }

  condition:
    any of them
}