rule TTP_XOR_MULT_DOSStub_959b {
  strings:
    $key_959b = { c1 f3 [2] b5 eb [2] f2 e9 [2] b5 f8 [2] fb f4 [2] f7 fe [2] e0 f5 [2] fb bb [2] c6 }

  condition:
    any of them
}