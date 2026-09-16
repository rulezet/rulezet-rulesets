rule TTP_XOR_MULT_DOSStub_f28f {
  strings:
    $key_f28f = { a6 e7 [2] d2 ff [2] 95 fd [2] d2 ec [2] 9c e0 [2] 90 ea [2] 87 e1 [2] 9c af [2] a1 }

  condition:
    any of them
}