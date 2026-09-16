rule TTP_XOR_MULT_DOSStub_2cd6 {
  strings:
    $key_2cd6 = { 78 be [2] 0c a6 [2] 4b a4 [2] 0c b5 [2] 42 b9 [2] 4e b3 [2] 59 b8 [2] 42 f6 [2] 7f }

  condition:
    any of them
}