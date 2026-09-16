rule TTP_XOR_MULT_DOSStub_1ad8 {
  strings:
    $key_1ad8 = { 4e b0 [2] 3a a8 [2] 7d aa [2] 3a bb [2] 74 b7 [2] 78 bd [2] 6f b6 [2] 74 f8 [2] 49 }

  condition:
    any of them
}