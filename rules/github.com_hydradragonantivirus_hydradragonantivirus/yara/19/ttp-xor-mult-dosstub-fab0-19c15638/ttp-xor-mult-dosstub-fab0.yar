rule TTP_XOR_MULT_DOSStub_fab0 {
  strings:
    $key_fab0 = { ae d8 [2] da c0 [2] 9d c2 [2] da d3 [2] 94 df [2] 98 d5 [2] 8f de [2] 94 90 [2] a9 }

  condition:
    any of them
}