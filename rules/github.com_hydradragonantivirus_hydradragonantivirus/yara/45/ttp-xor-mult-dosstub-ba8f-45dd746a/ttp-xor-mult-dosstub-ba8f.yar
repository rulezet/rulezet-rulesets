rule TTP_XOR_MULT_DOSStub_ba8f {
  strings:
    $key_ba8f = { ee e7 [2] 9a ff [2] dd fd [2] 9a ec [2] d4 e0 [2] d8 ea [2] cf e1 [2] d4 af [2] e9 }

  condition:
    any of them
}