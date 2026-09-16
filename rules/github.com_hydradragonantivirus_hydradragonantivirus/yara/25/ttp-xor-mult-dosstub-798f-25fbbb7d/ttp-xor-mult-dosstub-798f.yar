rule TTP_XOR_MULT_DOSStub_798f {
  strings:
    $key_798f = { 2d e7 [2] 59 ff [2] 1e fd [2] 59 ec [2] 17 e0 [2] 1b ea [2] 0c e1 [2] 17 af [2] 2a }

  condition:
    any of them
}