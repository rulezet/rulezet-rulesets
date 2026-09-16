rule TTP_XOR_MULT_DOSStub_a70a {
  strings:
    $key_a70a = { f3 62 [2] 87 7a [2] c0 78 [2] 87 69 [2] c9 65 [2] c5 6f [2] d2 64 [2] c9 2a [2] f4 }

  condition:
    any of them
}