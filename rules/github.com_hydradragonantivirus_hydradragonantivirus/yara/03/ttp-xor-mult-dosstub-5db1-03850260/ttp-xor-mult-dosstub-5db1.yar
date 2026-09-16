rule TTP_XOR_MULT_DOSStub_5db1 {
  strings:
    $key_5db1 = { 09 d9 [2] 7d c1 [2] 3a c3 [2] 7d d2 [2] 33 de [2] 3f d4 [2] 28 df [2] 33 91 [2] 0e }

  condition:
    any of them
}