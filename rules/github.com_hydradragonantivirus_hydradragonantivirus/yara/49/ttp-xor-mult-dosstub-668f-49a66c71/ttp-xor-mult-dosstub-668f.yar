rule TTP_XOR_MULT_DOSStub_668f {
  strings:
    $key_668f = { 32 e7 [2] 46 ff [2] 01 fd [2] 46 ec [2] 08 e0 [2] 04 ea [2] 13 e1 [2] 08 af [2] 35 }

  condition:
    any of them
}