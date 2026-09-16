rule TTP_XOR_MULT_DOSStub_498f {
  strings:
    $key_498f = { 1d e7 [2] 69 ff [2] 2e fd [2] 69 ec [2] 27 e0 [2] 2b ea [2] 3c e1 [2] 27 af [2] 1a }

  condition:
    any of them
}