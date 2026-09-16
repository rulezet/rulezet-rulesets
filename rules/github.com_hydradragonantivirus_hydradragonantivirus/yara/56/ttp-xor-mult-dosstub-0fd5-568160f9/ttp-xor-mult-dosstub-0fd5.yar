rule TTP_XOR_MULT_DOSStub_0fd5 {
  strings:
    $key_0fd5 = { 5b bd [2] 2f a5 [2] 68 a7 [2] 2f b6 [2] 61 ba [2] 6d b0 [2] 7a bb [2] 61 f5 [2] 5c }

  condition:
    any of them
}