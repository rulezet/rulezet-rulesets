rule TTP_XOR_MULT_DOSStub_59d2 {
  strings:
    $key_59d2 = { 0d ba [2] 79 a2 [2] 3e a0 [2] 79 b1 [2] 37 bd [2] 3b b7 [2] 2c bc [2] 37 f2 [2] 0a }

  condition:
    any of them
}