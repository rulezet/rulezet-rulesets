rule TTP_XOR_MULT_DOSStub_518f {
  strings:
    $key_518f = { 05 e7 [2] 71 ff [2] 36 fd [2] 71 ec [2] 3f e0 [2] 33 ea [2] 24 e1 [2] 3f af [2] 02 }

  condition:
    any of them
}