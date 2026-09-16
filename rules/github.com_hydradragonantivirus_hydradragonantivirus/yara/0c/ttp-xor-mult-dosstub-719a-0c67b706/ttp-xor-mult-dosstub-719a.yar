rule TTP_XOR_MULT_DOSStub_719a {
  strings:
    $key_719a = { 25 f2 [2] 51 ea [2] 16 e8 [2] 51 f9 [2] 1f f5 [2] 13 ff [2] 04 f4 [2] 1f ba [2] 22 }

  condition:
    any of them
}