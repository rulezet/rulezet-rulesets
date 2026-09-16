rule TTP_XOR_MULT_DOSStub_b0a5 {
  strings:
    $key_b0a5 = { e4 cd [2] 90 d5 [2] d7 d7 [2] 90 c6 [2] de ca [2] d2 c0 [2] c5 cb [2] de 85 [2] e3 }

  condition:
    any of them
}