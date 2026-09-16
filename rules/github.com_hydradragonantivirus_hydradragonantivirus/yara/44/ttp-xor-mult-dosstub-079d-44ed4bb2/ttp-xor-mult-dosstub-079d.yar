rule TTP_XOR_MULT_DOSStub_079d {
  strings:
    $key_079d = { 53 f5 [2] 27 ed [2] 60 ef [2] 27 fe [2] 69 f2 [2] 65 f8 [2] 72 f3 [2] 69 bd [2] 54 }

  condition:
    any of them
}