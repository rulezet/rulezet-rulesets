rule TTP_XOR_MULT_DOSStub_c89c {
  strings:
    $key_c89c = { 9c f4 [2] e8 ec [2] af ee [2] e8 ff [2] a6 f3 [2] aa f9 [2] bd f2 [2] a6 bc [2] 9b }

  condition:
    any of them
}