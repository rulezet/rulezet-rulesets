rule TTP_XOR_MULT_DOSStub_aec2 {
  strings:
    $key_aec2 = { fa aa [2] 8e b2 [2] c9 b0 [2] 8e a1 [2] c0 ad [2] cc a7 [2] db ac [2] c0 e2 [2] fd }

  condition:
    any of them
}