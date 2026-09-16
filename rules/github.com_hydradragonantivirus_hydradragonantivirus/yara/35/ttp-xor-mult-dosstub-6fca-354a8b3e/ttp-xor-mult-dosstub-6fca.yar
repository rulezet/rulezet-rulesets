rule TTP_XOR_MULT_DOSStub_6fca {
  strings:
    $key_6fca = { 3b a2 [2] 4f ba [2] 08 b8 [2] 4f a9 [2] 01 a5 [2] 0d af [2] 1a a4 [2] 01 ea [2] 3c }

  condition:
    any of them
}