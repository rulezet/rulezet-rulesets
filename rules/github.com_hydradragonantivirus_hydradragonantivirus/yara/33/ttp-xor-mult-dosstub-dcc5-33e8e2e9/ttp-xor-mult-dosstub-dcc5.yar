rule TTP_XOR_MULT_DOSStub_dcc5 {
  strings:
    $key_dcc5 = { 88 ad [2] fc b5 [2] bb b7 [2] fc a6 [2] b2 aa [2] be a0 [2] a9 ab [2] b2 e5 [2] 8f }

  condition:
    any of them
}