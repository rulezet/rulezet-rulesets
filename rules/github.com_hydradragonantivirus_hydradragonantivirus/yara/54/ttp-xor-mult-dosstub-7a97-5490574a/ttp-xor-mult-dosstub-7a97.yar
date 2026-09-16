rule TTP_XOR_MULT_DOSStub_7a97 {
  strings:
    $key_7a97 = { 2e ff [2] 5a e7 [2] 1d e5 [2] 5a f4 [2] 14 f8 [2] 18 f2 [2] 0f f9 [2] 14 b7 [2] 29 }

  condition:
    any of them
}