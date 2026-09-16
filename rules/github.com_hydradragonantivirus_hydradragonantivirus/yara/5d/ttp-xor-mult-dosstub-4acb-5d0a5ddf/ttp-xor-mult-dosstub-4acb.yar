rule TTP_XOR_MULT_DOSStub_4acb {
  strings:
    $key_4acb = { 1e a3 [2] 6a bb [2] 2d b9 [2] 6a a8 [2] 24 a4 [2] 28 ae [2] 3f a5 [2] 24 eb [2] 19 }

  condition:
    any of them
}