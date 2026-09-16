rule TTP_XOR_MULT_DOSStub_dcc1 {
  strings:
    $key_dcc1 = { 88 a9 [2] fc b1 [2] bb b3 [2] fc a2 [2] b2 ae [2] be a4 [2] a9 af [2] b2 e1 [2] 8f }

  condition:
    any of them
}