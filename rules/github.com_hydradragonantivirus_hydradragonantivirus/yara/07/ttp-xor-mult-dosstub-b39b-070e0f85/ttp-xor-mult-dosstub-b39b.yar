rule TTP_XOR_MULT_DOSStub_b39b {
  strings:
    $key_b39b = { e7 f3 [2] 93 eb [2] d4 e9 [2] 93 f8 [2] dd f4 [2] d1 fe [2] c6 f5 [2] dd bb [2] e0 }

  condition:
    any of them
}