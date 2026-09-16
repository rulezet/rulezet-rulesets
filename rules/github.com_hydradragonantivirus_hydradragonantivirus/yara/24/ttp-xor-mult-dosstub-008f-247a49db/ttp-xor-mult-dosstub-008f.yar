rule TTP_XOR_MULT_DOSStub_008f {
  strings:
    $key_008f = { 54 e7 [2] 20 ff [2] 67 fd [2] 20 ec [2] 6e e0 [2] 62 ea [2] 75 e1 [2] 6e af [2] 53 }

  condition:
    any of them
}