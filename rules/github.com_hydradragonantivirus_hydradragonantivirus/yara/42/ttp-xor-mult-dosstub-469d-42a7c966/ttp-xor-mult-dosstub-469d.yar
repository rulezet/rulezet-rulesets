rule TTP_XOR_MULT_DOSStub_469d {
  strings:
    $key_469d = { 12 f5 [2] 66 ed [2] 21 ef [2] 66 fe [2] 28 f2 [2] 24 f8 [2] 33 f3 [2] 28 bd [2] 15 }

  condition:
    any of them
}