rule TTP_XOR_MULT_DOSStub_c0ce {
  strings:
    $key_c0ce = { 94 a6 [2] e0 be [2] a7 bc [2] e0 ad [2] ae a1 [2] a2 ab [2] b5 a0 [2] ae ee [2] 93 }

  condition:
    any of them
}