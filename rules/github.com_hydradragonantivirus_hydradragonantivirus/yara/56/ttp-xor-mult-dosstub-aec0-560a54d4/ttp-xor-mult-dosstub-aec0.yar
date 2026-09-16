rule TTP_XOR_MULT_DOSStub_aec0 {
  strings:
    $key_aec0 = { fa a8 [2] 8e b0 [2] c9 b2 [2] 8e a3 [2] c0 af [2] cc a5 [2] db ae [2] c0 e0 [2] fd }

  condition:
    any of them
}