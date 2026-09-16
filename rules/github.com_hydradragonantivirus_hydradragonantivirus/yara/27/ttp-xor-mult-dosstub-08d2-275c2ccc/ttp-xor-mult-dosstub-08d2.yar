rule TTP_XOR_MULT_DOSStub_08d2 {
  strings:
    $key_08d2 = { 5c ba [2] 28 a2 [2] 6f a0 [2] 28 b1 [2] 66 bd [2] 6a b7 [2] 7d bc [2] 66 f2 [2] 5b }

  condition:
    any of them
}