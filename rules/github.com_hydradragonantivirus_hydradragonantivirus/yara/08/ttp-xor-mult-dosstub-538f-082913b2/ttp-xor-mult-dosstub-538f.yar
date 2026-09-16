rule TTP_XOR_MULT_DOSStub_538f {
  strings:
    $key_538f = { 07 e7 [2] 73 ff [2] 34 fd [2] 73 ec [2] 3d e0 [2] 31 ea [2] 26 e1 [2] 3d af [2] 00 }

  condition:
    any of them
}