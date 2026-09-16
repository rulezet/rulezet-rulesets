rule TTP_XOR_MULT_DOSStub_418f {
  strings:
    $key_418f = { 15 e7 [2] 61 ff [2] 26 fd [2] 61 ec [2] 2f e0 [2] 23 ea [2] 34 e1 [2] 2f af [2] 12 }

  condition:
    any of them
}