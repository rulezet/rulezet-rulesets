rule TTP_XOR_MULT_DOSStub_2db1 {
  strings:
    $key_2db1 = { 79 d9 [2] 0d c1 [2] 4a c3 [2] 0d d2 [2] 43 de [2] 4f d4 [2] 58 df [2] 43 91 [2] 7e }

  condition:
    any of them
}