rule TTP_XOR_MULT_DOSStub_f08f {
  strings:
    $key_f08f = { a4 e7 [2] d0 ff [2] 97 fd [2] d0 ec [2] 9e e0 [2] 92 ea [2] 85 e1 [2] 9e af [2] a3 }

  condition:
    any of them
}