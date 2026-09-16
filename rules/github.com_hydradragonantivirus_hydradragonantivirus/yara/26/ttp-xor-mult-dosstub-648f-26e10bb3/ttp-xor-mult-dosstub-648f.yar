rule TTP_XOR_MULT_DOSStub_648f {
  strings:
    $key_648f = { 30 e7 [2] 44 ff [2] 03 fd [2] 44 ec [2] 0a e0 [2] 06 ea [2] 11 e1 [2] 0a af [2] 37 }

  condition:
    any of them
}