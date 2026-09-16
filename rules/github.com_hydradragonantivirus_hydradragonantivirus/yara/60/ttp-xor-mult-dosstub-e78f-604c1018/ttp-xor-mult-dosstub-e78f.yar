rule TTP_XOR_MULT_DOSStub_e78f {
  strings:
    $key_e78f = { b3 e7 [2] c7 ff [2] 80 fd [2] c7 ec [2] 89 e0 [2] 85 ea [2] 92 e1 [2] 89 af [2] b4 }

  condition:
    any of them
}