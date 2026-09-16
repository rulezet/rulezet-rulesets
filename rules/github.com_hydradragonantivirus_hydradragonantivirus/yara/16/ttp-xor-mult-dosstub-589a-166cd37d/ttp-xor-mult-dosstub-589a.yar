rule TTP_XOR_MULT_DOSStub_589a {
  strings:
    $key_589a = { 0c f2 [2] 78 ea [2] 3f e8 [2] 78 f9 [2] 36 f5 [2] 3a ff [2] 2d f4 [2] 36 ba [2] 0b }

  condition:
    any of them
}