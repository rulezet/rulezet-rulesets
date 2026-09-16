rule TTP_XOR_MULT_DOSStub_3fca {
  strings:
    $key_3fca = { 6b a2 [2] 1f ba [2] 58 b8 [2] 1f a9 [2] 51 a5 [2] 5d af [2] 4a a4 [2] 51 ea [2] 6c }

  condition:
    any of them
}