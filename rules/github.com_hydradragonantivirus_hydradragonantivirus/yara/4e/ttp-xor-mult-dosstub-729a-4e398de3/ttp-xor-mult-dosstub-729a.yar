rule TTP_XOR_MULT_DOSStub_729a {
  strings:
    $key_729a = { 26 f2 [2] 52 ea [2] 15 e8 [2] 52 f9 [2] 1c f5 [2] 10 ff [2] 07 f4 [2] 1c ba [2] 21 }

  condition:
    any of them
}