rule TTP_XOR_MULT_DOSStub_4a97 {
  strings:
    $key_4a97 = { 1e ff [2] 6a e7 [2] 2d e5 [2] 6a f4 [2] 24 f8 [2] 28 f2 [2] 3f f9 [2] 24 b7 [2] 19 }

  condition:
    any of them
}