rule TTP_XOR_MULT_DOSStub_5bd2 {
  strings:
    $key_5bd2 = { 0f ba [2] 7b a2 [2] 3c a0 [2] 7b b1 [2] 35 bd [2] 39 b7 [2] 2e bc [2] 35 f2 [2] 08 }

  condition:
    any of them
}