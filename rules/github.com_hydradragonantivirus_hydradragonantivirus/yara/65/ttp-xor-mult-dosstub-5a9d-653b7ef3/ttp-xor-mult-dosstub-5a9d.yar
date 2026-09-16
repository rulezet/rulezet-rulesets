rule TTP_XOR_MULT_DOSStub_5a9d {
  strings:
    $key_5a9d = { 0e f5 [2] 7a ed [2] 3d ef [2] 7a fe [2] 34 f2 [2] 38 f8 [2] 2f f3 [2] 34 bd [2] 09 }

  condition:
    any of them
}