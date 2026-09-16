rule TTP_XOR_MULT_DOSStub_c7ce {
  strings:
    $key_c7ce = { 93 a6 [2] e7 be [2] a0 bc [2] e7 ad [2] a9 a1 [2] a5 ab [2] b2 a0 [2] a9 ee [2] 94 }

  condition:
    any of them
}