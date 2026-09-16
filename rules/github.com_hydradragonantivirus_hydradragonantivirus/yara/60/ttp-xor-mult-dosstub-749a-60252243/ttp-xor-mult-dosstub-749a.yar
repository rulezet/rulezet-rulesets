rule TTP_XOR_MULT_DOSStub_749a {
  strings:
    $key_749a = { 20 f2 [2] 54 ea [2] 13 e8 [2] 54 f9 [2] 1a f5 [2] 16 ff [2] 01 f4 [2] 1a ba [2] 27 }

  condition:
    any of them
}