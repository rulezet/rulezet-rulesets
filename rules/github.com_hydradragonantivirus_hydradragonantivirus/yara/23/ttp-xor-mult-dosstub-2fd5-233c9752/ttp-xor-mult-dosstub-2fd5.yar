rule TTP_XOR_MULT_DOSStub_2fd5 {
  strings:
    $key_2fd5 = { 7b bd [2] 0f a5 [2] 48 a7 [2] 0f b6 [2] 41 ba [2] 4d b0 [2] 5a bb [2] 41 f5 [2] 7c }

  condition:
    any of them
}