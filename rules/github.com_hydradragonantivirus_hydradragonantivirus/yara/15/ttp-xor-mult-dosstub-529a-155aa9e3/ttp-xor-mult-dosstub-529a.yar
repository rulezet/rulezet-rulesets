rule TTP_XOR_MULT_DOSStub_529a {
  strings:
    $key_529a = { 06 f2 [2] 72 ea [2] 35 e8 [2] 72 f9 [2] 3c f5 [2] 30 ff [2] 27 f4 [2] 3c ba [2] 01 }

  condition:
    any of them
}