rule TTP_XOR_MULT_DOSStub_c8cb {
  strings:
    $key_c8cb = { 9c a3 [2] e8 bb [2] af b9 [2] e8 a8 [2] a6 a4 [2] aa ae [2] bd a5 [2] a6 eb [2] 9b }

  condition:
    any of them
}