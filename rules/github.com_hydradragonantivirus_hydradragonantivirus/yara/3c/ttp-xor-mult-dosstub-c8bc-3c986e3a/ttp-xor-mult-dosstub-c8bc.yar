rule TTP_XOR_MULT_DOSStub_c8bc {
  strings:
    $key_c8bc = { 9c d4 [2] e8 cc [2] af ce [2] e8 df [2] a6 d3 [2] aa d9 [2] bd d2 [2] a6 9c [2] 9b }

  condition:
    any of them
}