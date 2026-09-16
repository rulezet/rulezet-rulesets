rule TTP_XOR_MULT_DOSStub_3bd2 {
  strings:
    $key_3bd2 = { 6f ba [2] 1b a2 [2] 5c a0 [2] 1b b1 [2] 55 bd [2] 59 b7 [2] 4e bc [2] 55 f2 [2] 68 }

  condition:
    any of them
}