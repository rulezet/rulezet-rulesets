rule TTP_XOR_MULT_DOSStub_a79d {
  strings:
    $key_a79d = { f3 f5 [2] 87 ed [2] c0 ef [2] 87 fe [2] c9 f2 [2] c5 f8 [2] d2 f3 [2] c9 bd [2] f4 }

  condition:
    any of them
}