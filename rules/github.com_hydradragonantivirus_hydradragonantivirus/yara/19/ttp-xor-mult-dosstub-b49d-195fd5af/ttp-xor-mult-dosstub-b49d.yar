rule TTP_XOR_MULT_DOSStub_b49d {
  strings:
    $key_b49d = { e0 f5 [2] 94 ed [2] d3 ef [2] 94 fe [2] da f2 [2] d6 f8 [2] c1 f3 [2] da bd [2] e7 }

  condition:
    any of them
}