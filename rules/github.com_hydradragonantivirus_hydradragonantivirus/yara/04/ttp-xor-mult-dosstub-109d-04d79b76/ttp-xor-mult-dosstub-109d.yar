rule TTP_XOR_MULT_DOSStub_109d {
  strings:
    $key_109d = { 44 f5 [2] 30 ed [2] 77 ef [2] 30 fe [2] 7e f2 [2] 72 f8 [2] 65 f3 [2] 7e bd [2] 43 }

  condition:
    any of them
}