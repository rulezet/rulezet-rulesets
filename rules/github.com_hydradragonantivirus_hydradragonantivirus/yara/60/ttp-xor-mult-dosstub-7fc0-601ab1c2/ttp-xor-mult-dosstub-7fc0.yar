rule TTP_XOR_MULT_DOSStub_7fc0 {
  strings:
    $key_7fc0 = { 2b a8 [2] 5f b0 [2] 18 b2 [2] 5f a3 [2] 11 af [2] 1d a5 [2] 0a ae [2] 11 e0 [2] 2c }

  condition:
    any of them
}