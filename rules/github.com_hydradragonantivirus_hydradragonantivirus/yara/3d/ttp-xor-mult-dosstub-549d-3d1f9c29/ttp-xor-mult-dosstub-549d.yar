rule TTP_XOR_MULT_DOSStub_549d {
  strings:
    $key_549d = { 00 f5 [2] 74 ed [2] 33 ef [2] 74 fe [2] 3a f2 [2] 36 f8 [2] 21 f3 [2] 3a bd [2] 07 }

  condition:
    any of them
}