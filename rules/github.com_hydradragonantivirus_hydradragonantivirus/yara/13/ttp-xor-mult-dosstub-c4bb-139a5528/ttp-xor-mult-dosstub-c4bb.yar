rule TTP_XOR_MULT_DOSStub_c4bb {
  strings:
    $key_c4bb = { 90 d3 [2] e4 cb [2] a3 c9 [2] e4 d8 [2] aa d4 [2] a6 de [2] b1 d5 [2] aa 9b [2] 97 }

  condition:
    any of them
}