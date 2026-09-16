rule TTP_XOR_MULT_DOSStub_22ca {
  strings:
    $key_22ca = { 76 a2 [2] 02 ba [2] 45 b8 [2] 02 a9 [2] 4c a5 [2] 40 af [2] 57 a4 [2] 4c ea [2] 71 }

  condition:
    any of them
}