rule TTP_XOR_MULT_DOSStub_039a {
  strings:
    $key_039a = { 57 f2 [2] 23 ea [2] 64 e8 [2] 23 f9 [2] 6d f5 [2] 61 ff [2] 76 f4 [2] 6d ba [2] 50 }

  condition:
    any of them
}