rule TTP_XOR_MULT_DOSStub_0db1 {
  strings:
    $key_0db1 = { 59 d9 [2] 2d c1 [2] 6a c3 [2] 2d d2 [2] 63 de [2] 6f d4 [2] 78 df [2] 63 91 [2] 5e }

  condition:
    any of them
}