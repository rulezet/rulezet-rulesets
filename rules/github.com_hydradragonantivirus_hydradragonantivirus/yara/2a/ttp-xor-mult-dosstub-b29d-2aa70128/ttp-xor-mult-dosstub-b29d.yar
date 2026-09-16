rule TTP_XOR_MULT_DOSStub_b29d {
  strings:
    $key_b29d = { e6 f5 [2] 92 ed [2] d5 ef [2] 92 fe [2] dc f2 [2] d0 f8 [2] c7 f3 [2] dc bd [2] e1 }

  condition:
    any of them
}