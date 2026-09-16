rule TTP_XOR_MULT_DOSStub_dcc2 {
  strings:
    $key_dcc2 = { 88 aa [2] fc b2 [2] bb b0 [2] fc a1 [2] b2 ad [2] be a7 [2] a9 ac [2] b2 e2 [2] 8f }

  condition:
    any of them
}