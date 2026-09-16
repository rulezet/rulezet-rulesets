rule TTP_XOR_MULT_DOSStub_aec9 {
  strings:
    $key_aec9 = { fa a1 [2] 8e b9 [2] c9 bb [2] 8e aa [2] c0 a6 [2] cc ac [2] db a7 [2] c0 e9 [2] fd }

  condition:
    any of them
}