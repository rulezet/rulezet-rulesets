rule TTP_XOR_MULT_DOSStub_bad8 {
  strings:
    $key_bad8 = { ee b0 [2] 9a a8 [2] dd aa [2] 9a bb [2] d4 b7 [2] d8 bd [2] cf b6 [2] d4 f8 [2] e9 }

  condition:
    any of them
}