rule TTP_XOR_MULT_DOSStub_2a9d {
  strings:
    $key_2a9d = { 7e f5 [2] 0a ed [2] 4d ef [2] 0a fe [2] 44 f2 [2] 48 f8 [2] 5f f3 [2] 44 bd [2] 79 }

  condition:
    any of them
}