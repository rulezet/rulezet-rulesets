rule TTP_XOR_MULT_DOSStub_26ca {
  strings:
    $key_26ca = { 72 a2 [2] 06 ba [2] 41 b8 [2] 06 a9 [2] 48 a5 [2] 44 af [2] 53 a4 [2] 48 ea [2] 75 }

  condition:
    any of them
}