rule TTP_XOR_MULT_DOSStub_098f {
  strings:
    $key_098f = { 5d e7 [2] 29 ff [2] 6e fd [2] 29 ec [2] 67 e0 [2] 6b ea [2] 7c e1 [2] 67 af [2] 5a }

  condition:
    any of them
}