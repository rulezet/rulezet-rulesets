rule TTP_XOR_MULT_DOSStub_e745 {
  strings:
    $key_e745 = { b3 2d [2] c7 35 [2] 80 37 [2] c7 26 [2] 89 2a [2] 85 20 [2] 92 2b [2] 89 65 [2] b4 }

  condition:
    any of them
}