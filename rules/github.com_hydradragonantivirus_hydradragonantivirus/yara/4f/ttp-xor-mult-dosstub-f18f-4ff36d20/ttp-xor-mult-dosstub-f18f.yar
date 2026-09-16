rule TTP_XOR_MULT_DOSStub_f18f {
  strings:
    $key_f18f = { a5 e7 [2] d1 ff [2] 96 fd [2] d1 ec [2] 9f e0 [2] 93 ea [2] 84 e1 [2] 9f af [2] a2 }

  condition:
    any of them
}