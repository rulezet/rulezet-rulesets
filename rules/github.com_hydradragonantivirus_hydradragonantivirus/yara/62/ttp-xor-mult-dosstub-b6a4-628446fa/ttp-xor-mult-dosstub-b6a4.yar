rule TTP_XOR_MULT_DOSStub_b6a4 {
  strings:
    $key_b6a4 = { e2 cc [2] 96 d4 [2] d1 d6 [2] 96 c7 [2] d8 cb [2] d4 c1 [2] c3 ca [2] d8 84 [2] e5 }

  condition:
    any of them
}