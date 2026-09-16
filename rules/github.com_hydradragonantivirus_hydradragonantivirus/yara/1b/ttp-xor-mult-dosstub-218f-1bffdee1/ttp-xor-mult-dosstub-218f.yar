rule TTP_XOR_MULT_DOSStub_218f {
  strings:
    $key_218f = { 75 e7 [2] 01 ff [2] 46 fd [2] 01 ec [2] 4f e0 [2] 43 ea [2] 54 e1 [2] 4f af [2] 72 }

  condition:
    any of them
}