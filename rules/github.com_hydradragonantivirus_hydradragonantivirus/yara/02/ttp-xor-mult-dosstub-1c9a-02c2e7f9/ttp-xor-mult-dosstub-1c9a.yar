rule TTP_XOR_MULT_DOSStub_1c9a {
  strings:
    $key_1c9a = { 48 f2 [2] 3c ea [2] 7b e8 [2] 3c f9 [2] 72 f5 [2] 7e ff [2] 69 f4 [2] 72 ba [2] 4f }

  condition:
    any of them
}