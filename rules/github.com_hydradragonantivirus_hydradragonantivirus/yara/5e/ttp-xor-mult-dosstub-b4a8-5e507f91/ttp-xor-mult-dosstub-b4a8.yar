rule TTP_XOR_MULT_DOSStub_b4a8 {
  strings:
    $key_b4a8 = { e0 c0 [2] 94 d8 [2] d3 da [2] 94 cb [2] da c7 [2] d6 cd [2] c1 c6 [2] da 88 [2] e7 }

  condition:
    any of them
}