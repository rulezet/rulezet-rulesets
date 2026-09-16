rule TTP_XOR_MULT_DOSStub_a3b1 {
  strings:
    $key_a3b1 = { f7 d9 [2] 83 c1 [2] c4 c3 [2] 83 d2 [2] cd de [2] c1 d4 [2] d6 df [2] cd 91 [2] f0 }

  condition:
    any of them
}