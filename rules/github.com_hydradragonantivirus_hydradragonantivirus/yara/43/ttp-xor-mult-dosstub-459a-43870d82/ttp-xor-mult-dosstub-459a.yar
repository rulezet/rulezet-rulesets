rule TTP_XOR_MULT_DOSStub_459a {
  strings:
    $key_459a = { 11 f2 [2] 65 ea [2] 22 e8 [2] 65 f9 [2] 2b f5 [2] 27 ff [2] 30 f4 [2] 2b ba [2] 16 }

  condition:
    any of them
}