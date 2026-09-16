rule TTP_XOR_MULT_DOSStub_348f {
  strings:
    $key_348f = { 60 e7 [2] 14 ff [2] 53 fd [2] 14 ec [2] 5a e0 [2] 56 ea [2] 41 e1 [2] 5a af [2] 67 }

  condition:
    any of them
}