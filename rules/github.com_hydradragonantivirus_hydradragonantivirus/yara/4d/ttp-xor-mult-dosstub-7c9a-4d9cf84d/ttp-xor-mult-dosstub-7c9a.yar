rule TTP_XOR_MULT_DOSStub_7c9a {
  strings:
    $key_7c9a = { 28 f2 [2] 5c ea [2] 1b e8 [2] 5c f9 [2] 12 f5 [2] 1e ff [2] 09 f4 [2] 12 ba [2] 2f }

  condition:
    any of them
}