rule TTP_XOR_MULT_DOSStub_4ad8 {
  strings:
    $key_4ad8 = { 1e b0 [2] 6a a8 [2] 2d aa [2] 6a bb [2] 24 b7 [2] 28 bd [2] 3f b6 [2] 24 f8 [2] 19 }

  condition:
    any of them
}