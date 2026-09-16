rule TTP_XOR_MULT_DOSStub_169a {
  strings:
    $key_169a = { 42 f2 [2] 36 ea [2] 71 e8 [2] 36 f9 [2] 78 f5 [2] 74 ff [2] 63 f4 [2] 78 ba [2] 45 }

  condition:
    any of them
}