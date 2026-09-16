rule TTP_XOR_MULT_DOSStub_dcc7 {
  strings:
    $key_dcc7 = { 88 af [2] fc b7 [2] bb b5 [2] fc a4 [2] b2 a8 [2] be a2 [2] a9 a9 [2] b2 e7 [2] 8f }

  condition:
    any of them
}