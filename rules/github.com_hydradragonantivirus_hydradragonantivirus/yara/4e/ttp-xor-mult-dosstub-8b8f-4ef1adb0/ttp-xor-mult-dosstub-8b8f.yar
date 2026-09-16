rule TTP_XOR_MULT_DOSStub_8b8f {
  strings:
    $key_8b8f = { df e7 [2] ab ff [2] ec fd [2] ab ec [2] e5 e0 [2] e9 ea [2] fe e1 [2] e5 af [2] d8 }

  condition:
    any of them
}