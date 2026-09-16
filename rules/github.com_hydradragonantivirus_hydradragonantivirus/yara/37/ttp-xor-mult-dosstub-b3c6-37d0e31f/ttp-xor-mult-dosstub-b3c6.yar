rule TTP_XOR_MULT_DOSStub_b3c6 {
  strings:
    $key_b3c6 = { e7 ae [2] 93 b6 [2] d4 b4 [2] 93 a5 [2] dd a9 [2] d1 a3 [2] c6 a8 [2] dd e6 [2] e0 }

  condition:
    any of them
}