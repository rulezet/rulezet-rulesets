rule TTP_XOR_MULT_DOSStub_fab1 {
  strings:
    $key_fab1 = { ae d9 [2] da c1 [2] 9d c3 [2] da d2 [2] 94 de [2] 98 d4 [2] 8f df [2] 94 91 [2] a9 }

  condition:
    any of them
}