rule TTP_XOR_MULT_DOSStub_e0d0 {
  strings:
    $key_e0d0 = { b4 b8 [2] c0 a0 [2] 87 a2 [2] c0 b3 [2] 8e bf [2] 82 b5 [2] 95 be [2] 8e f0 [2] b3 }

  condition:
    any of them
}