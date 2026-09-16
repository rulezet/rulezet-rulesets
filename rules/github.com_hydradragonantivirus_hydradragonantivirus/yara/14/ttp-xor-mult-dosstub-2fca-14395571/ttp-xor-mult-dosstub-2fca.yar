rule TTP_XOR_MULT_DOSStub_2fca {
  strings:
    $key_2fca = { 7b a2 [2] 0f ba [2] 48 b8 [2] 0f a9 [2] 41 a5 [2] 4d af [2] 5a a4 [2] 41 ea [2] 7c }

  condition:
    any of them
}