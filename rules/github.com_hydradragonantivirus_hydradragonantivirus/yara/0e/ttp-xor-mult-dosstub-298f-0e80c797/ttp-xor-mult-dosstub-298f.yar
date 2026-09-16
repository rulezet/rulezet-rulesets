rule TTP_XOR_MULT_DOSStub_298f {
  strings:
    $key_298f = { 7d e7 [2] 09 ff [2] 4e fd [2] 09 ec [2] 47 e0 [2] 4b ea [2] 5c e1 [2] 47 af [2] 7a }

  condition:
    any of them
}