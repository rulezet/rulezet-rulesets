rule TTP_XOR_MULT_DOSStub_b0bc {
  strings:
    $key_b0bc = { e4 d4 [2] 90 cc [2] d7 ce [2] 90 df [2] de d3 [2] d2 d9 [2] c5 d2 [2] de 9c [2] e3 }

  condition:
    any of them
}