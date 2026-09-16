rule TTP_XOR_MULT_DOSStub_069a {
  strings:
    $key_069a = { 52 f2 [2] 26 ea [2] 61 e8 [2] 26 f9 [2] 68 f5 [2] 64 ff [2] 73 f4 [2] 68 ba [2] 55 }

  condition:
    any of them
}