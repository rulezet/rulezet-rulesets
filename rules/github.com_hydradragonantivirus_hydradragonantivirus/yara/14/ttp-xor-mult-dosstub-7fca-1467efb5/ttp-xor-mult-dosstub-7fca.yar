rule TTP_XOR_MULT_DOSStub_7fca {
  strings:
    $key_7fca = { 2b a2 [2] 5f ba [2] 18 b8 [2] 5f a9 [2] 11 a5 [2] 1d af [2] 0a a4 [2] 11 ea [2] 2c }

  condition:
    any of them
}