rule TTP_XOR_MULT_DOSStub_0a9d {
  strings:
    $key_0a9d = { 5e f5 [2] 2a ed [2] 6d ef [2] 2a fe [2] 64 f2 [2] 68 f8 [2] 7f f3 [2] 64 bd [2] 59 }

  condition:
    any of them
}