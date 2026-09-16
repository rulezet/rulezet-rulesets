rule TTP_XOR_MULT_DOSStub_b9c2 {
  strings:
    $key_b9c2 = { ed aa [2] 99 b2 [2] de b0 [2] 99 a1 [2] d7 ad [2] db a7 [2] cc ac [2] d7 e2 [2] ea }

  condition:
    any of them
}