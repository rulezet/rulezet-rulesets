rule TTP_XOR_MULT_DOSStub_6db1 {
  strings:
    $key_6db1 = { 39 d9 [2] 4d c1 [2] 0a c3 [2] 4d d2 [2] 03 de [2] 0f d4 [2] 18 df [2] 03 91 [2] 3e }

  condition:
    any of them
}