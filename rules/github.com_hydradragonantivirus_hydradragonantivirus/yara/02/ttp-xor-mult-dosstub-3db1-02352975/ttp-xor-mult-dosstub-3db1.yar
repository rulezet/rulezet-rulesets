rule TTP_XOR_MULT_DOSStub_3db1 {
  strings:
    $key_3db1 = { 69 d9 [2] 1d c1 [2] 5a c3 [2] 1d d2 [2] 53 de [2] 5f d4 [2] 48 df [2] 53 91 [2] 6e }

  condition:
    any of them
}