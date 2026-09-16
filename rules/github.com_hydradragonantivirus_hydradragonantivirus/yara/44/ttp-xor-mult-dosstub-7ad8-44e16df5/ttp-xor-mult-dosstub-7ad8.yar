rule TTP_XOR_MULT_DOSStub_7ad8 {
  strings:
    $key_7ad8 = { 2e b0 [2] 5a a8 [2] 1d aa [2] 5a bb [2] 14 b7 [2] 18 bd [2] 0f b6 [2] 14 f8 [2] 29 }

  condition:
    any of them
}