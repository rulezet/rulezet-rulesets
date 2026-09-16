rule TTP_XOR_MULT_DOSStub_29d4 {
  strings:
    $key_29d4 = { 7d bc [2] 09 a4 [2] 4e a6 [2] 09 b7 [2] 47 bb [2] 4b b1 [2] 5c ba [2] 47 f4 [2] 7a }

  condition:
    any of them
}