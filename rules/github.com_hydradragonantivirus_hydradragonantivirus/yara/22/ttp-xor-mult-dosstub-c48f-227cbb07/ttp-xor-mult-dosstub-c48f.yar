rule TTP_XOR_MULT_DOSStub_c48f {
  strings:
    $key_c48f = { 90 e7 [2] e4 ff [2] a3 fd [2] e4 ec [2] aa e0 [2] a6 ea [2] b1 e1 [2] aa af [2] 97 }

  condition:
    any of them
}