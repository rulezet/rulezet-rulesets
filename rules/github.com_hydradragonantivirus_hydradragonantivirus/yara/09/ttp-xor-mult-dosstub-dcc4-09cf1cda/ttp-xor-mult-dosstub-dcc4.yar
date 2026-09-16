rule TTP_XOR_MULT_DOSStub_dcc4 {
  strings:
    $key_dcc4 = { 88 ac [2] fc b4 [2] bb b6 [2] fc a7 [2] b2 ab [2] be a1 [2] a9 aa [2] b2 e4 [2] 8f }

  condition:
    any of them
}