rule TTP_XOR_MULT_DOSStub_709d {
  strings:
    $key_709d = { 24 f5 [2] 50 ed [2] 17 ef [2] 50 fe [2] 1e f2 [2] 12 f8 [2] 05 f3 [2] 1e bd [2] 23 }

  condition:
    any of them
}