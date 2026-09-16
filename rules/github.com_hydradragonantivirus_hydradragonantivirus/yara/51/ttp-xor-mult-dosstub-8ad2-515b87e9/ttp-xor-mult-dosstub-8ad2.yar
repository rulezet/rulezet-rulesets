rule TTP_XOR_MULT_DOSStub_8ad2 {
  strings:
    $key_8ad2 = { de ba [2] aa a2 [2] ed a0 [2] aa b1 [2] e4 bd [2] e8 b7 [2] ff bc [2] e4 f2 [2] d9 }

  condition:
    any of them
}