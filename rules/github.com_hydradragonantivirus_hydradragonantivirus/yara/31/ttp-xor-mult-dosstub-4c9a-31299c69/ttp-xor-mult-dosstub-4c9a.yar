rule TTP_XOR_MULT_DOSStub_4c9a {
  strings:
    $key_4c9a = { 18 f2 [2] 6c ea [2] 2b e8 [2] 6c f9 [2] 22 f5 [2] 2e ff [2] 39 f4 [2] 22 ba [2] 1f }

  condition:
    any of them
}