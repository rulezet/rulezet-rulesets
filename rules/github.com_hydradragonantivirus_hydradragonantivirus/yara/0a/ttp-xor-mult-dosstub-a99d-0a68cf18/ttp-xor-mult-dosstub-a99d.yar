rule TTP_XOR_MULT_DOSStub_a99d {
  strings:
    $key_a99d = { fd f5 [2] 89 ed [2] ce ef [2] 89 fe [2] c7 f2 [2] cb f8 [2] dc f3 [2] c7 bd [2] fa }

  condition:
    any of them
}