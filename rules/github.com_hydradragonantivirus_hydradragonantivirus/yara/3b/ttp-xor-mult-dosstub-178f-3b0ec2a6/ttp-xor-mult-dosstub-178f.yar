rule TTP_XOR_MULT_DOSStub_178f {
  strings:
    $key_178f = { 43 e7 [2] 37 ff [2] 70 fd [2] 37 ec [2] 79 e0 [2] 75 ea [2] 62 e1 [2] 79 af [2] 44 }

  condition:
    any of them
}