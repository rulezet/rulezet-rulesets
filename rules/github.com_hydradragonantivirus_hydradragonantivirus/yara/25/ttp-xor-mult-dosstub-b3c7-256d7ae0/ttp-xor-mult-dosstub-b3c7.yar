rule TTP_XOR_MULT_DOSStub_b3c7 {
  strings:
    $key_b3c7 = { e7 af [2] 93 b7 [2] d4 b5 [2] 93 a4 [2] dd a8 [2] d1 a2 [2] c6 a9 [2] dd e7 [2] e0 }

  condition:
    any of them
}