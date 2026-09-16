rule TTP_XOR_MULT_DOSStub_c58f {
  strings:
    $key_c58f = { 91 e7 [2] e5 ff [2] a2 fd [2] e5 ec [2] ab e0 [2] a7 ea [2] b0 e1 [2] ab af [2] 96 }

  condition:
    any of them
}