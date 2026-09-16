rule TTP_XOR_MULT_DOSStub_ab8c {
  strings:
    $key_ab8c = { ff e4 [2] 8b fc [2] cc fe [2] 8b ef [2] c5 e3 [2] c9 e9 [2] de e2 [2] c5 ac [2] f8 }

  condition:
    any of them
}