rule TTP_XOR_MULT_DOSStub_dc8c {
  strings:
    $key_dc8c = { 88 e4 [2] fc fc [2] bb fe [2] fc ef [2] b2 e3 [2] be e9 [2] a9 e2 [2] b2 ac [2] 8f }

  condition:
    any of them
}