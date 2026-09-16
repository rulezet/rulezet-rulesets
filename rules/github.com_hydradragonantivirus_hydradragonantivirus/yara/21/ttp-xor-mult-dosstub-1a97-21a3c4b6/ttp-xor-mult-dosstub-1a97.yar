rule TTP_XOR_MULT_DOSStub_1a97 {
  strings:
    $key_1a97 = { 4e ff [2] 3a e7 [2] 7d e5 [2] 3a f4 [2] 74 f8 [2] 78 f2 [2] 6f f9 [2] 74 b7 [2] 49 }

  condition:
    any of them
}