rule TTP_XOR_MULT_DOSStub_6ad8 {
  strings:
    $key_6ad8 = { 3e b0 [2] 4a a8 [2] 0d aa [2] 4a bb [2] 04 b7 [2] 08 bd [2] 1f b6 [2] 04 f8 [2] 39 }

  condition:
    any of them
}