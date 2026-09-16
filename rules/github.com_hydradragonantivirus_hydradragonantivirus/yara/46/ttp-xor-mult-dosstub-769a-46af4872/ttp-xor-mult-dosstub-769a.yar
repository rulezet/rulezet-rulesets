rule TTP_XOR_MULT_DOSStub_769a {
  strings:
    $key_769a = { 22 f2 [2] 56 ea [2] 11 e8 [2] 56 f9 [2] 18 f5 [2] 14 ff [2] 03 f4 [2] 18 ba [2] 25 }

  condition:
    any of them
}