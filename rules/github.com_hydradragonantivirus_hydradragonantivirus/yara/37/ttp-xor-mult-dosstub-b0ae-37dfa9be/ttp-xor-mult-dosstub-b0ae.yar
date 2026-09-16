rule TTP_XOR_MULT_DOSStub_b0ae {
  strings:
    $key_b0ae = { e4 c6 [2] 90 de [2] d7 dc [2] 90 cd [2] de c1 [2] d2 cb [2] c5 c0 [2] de 8e [2] e3 }

  condition:
    any of them
}