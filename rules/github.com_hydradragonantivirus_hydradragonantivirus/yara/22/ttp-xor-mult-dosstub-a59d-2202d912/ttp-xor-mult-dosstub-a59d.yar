rule TTP_XOR_MULT_DOSStub_a59d {
  strings:
    $key_a59d = { f1 f5 [2] 85 ed [2] c2 ef [2] 85 fe [2] cb f2 [2] c7 f8 [2] d0 f3 [2] cb bd [2] f6 }

  condition:
    any of them
}