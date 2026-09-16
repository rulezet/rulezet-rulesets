rule TTP_XOR_MULT_DOSStub_c080 {
  strings:
    $key_c080 = { 94 e8 [2] e0 f0 [2] a7 f2 [2] e0 e3 [2] ae ef [2] a2 e5 [2] b5 ee [2] ae a0 [2] 93 }

  condition:
    any of them
}