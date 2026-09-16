rule TTP_XOR_MULT_DOSStub_398f {
  strings:
    $key_398f = { 6d e7 [2] 19 ff [2] 5e fd [2] 19 ec [2] 57 e0 [2] 5b ea [2] 4c e1 [2] 57 af [2] 6a }

  condition:
    any of them
}