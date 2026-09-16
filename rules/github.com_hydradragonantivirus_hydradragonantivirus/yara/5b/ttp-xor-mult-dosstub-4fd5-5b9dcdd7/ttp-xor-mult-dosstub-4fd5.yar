rule TTP_XOR_MULT_DOSStub_4fd5 {
  strings:
    $key_4fd5 = { 1b bd [2] 6f a5 [2] 28 a7 [2] 6f b6 [2] 21 ba [2] 2d b0 [2] 3a bb [2] 21 f5 [2] 1c }

  condition:
    any of them
}