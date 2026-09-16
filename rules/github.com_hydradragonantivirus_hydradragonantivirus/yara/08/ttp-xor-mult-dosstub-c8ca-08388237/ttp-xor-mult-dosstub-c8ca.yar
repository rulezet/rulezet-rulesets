rule TTP_XOR_MULT_DOSStub_c8ca {
  strings:
    $key_c8ca = { 9c a2 [2] e8 ba [2] af b8 [2] e8 a9 [2] a6 a5 [2] aa af [2] bd a4 [2] a6 ea [2] 9b }

  condition:
    any of them
}