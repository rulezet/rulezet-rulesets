rule TTP_XOR_MULT_DOSStub_87ca {
  strings:
    $key_87ca = { d3 a2 [2] a7 ba [2] e0 b8 [2] a7 a9 [2] e9 a5 [2] e5 af [2] f2 a4 [2] e9 ea [2] d4 }

  condition:
    any of them
}