rule TTP_XOR_MULT_DOSStub_4a9d {
  strings:
    $key_4a9d = { 1e f5 [2] 6a ed [2] 2d ef [2] 6a fe [2] 24 f2 [2] 28 f8 [2] 3f f3 [2] 24 bd [2] 19 }

  condition:
    any of them
}