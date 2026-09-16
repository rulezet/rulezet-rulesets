rule TTP_XOR_MULT_DOSStub_5fd5 {
  strings:
    $key_5fd5 = { 0b bd [2] 7f a5 [2] 38 a7 [2] 7f b6 [2] 31 ba [2] 3d b0 [2] 2a bb [2] 31 f5 [2] 0c }

  condition:
    any of them
}