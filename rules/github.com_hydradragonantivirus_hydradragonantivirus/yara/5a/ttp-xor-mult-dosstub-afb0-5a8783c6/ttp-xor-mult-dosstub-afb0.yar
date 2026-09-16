rule TTP_XOR_MULT_DOSStub_afb0 {
  strings:
    $key_afb0 = { fb d8 [2] 8f c0 [2] c8 c2 [2] 8f d3 [2] c1 df [2] cd d5 [2] da de [2] c1 90 [2] fc }

  condition:
    any of them
}