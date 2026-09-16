rule TTP_XOR_MULT_DOSStub_7fd5 {
  strings:
    $key_7fd5 = { 2b bd [2] 5f a5 [2] 18 a7 [2] 5f b6 [2] 11 ba [2] 1d b0 [2] 0a bb [2] 11 f5 [2] 2c }

  condition:
    any of them
}