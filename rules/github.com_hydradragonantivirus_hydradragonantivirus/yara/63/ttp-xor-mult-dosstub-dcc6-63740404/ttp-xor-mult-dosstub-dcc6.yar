rule TTP_XOR_MULT_DOSStub_dcc6 {
  strings:
    $key_dcc6 = { 88 ae [2] fc b6 [2] bb b4 [2] fc a5 [2] b2 a9 [2] be a3 [2] a9 a8 [2] b2 e6 [2] 8f }

  condition:
    any of them
}