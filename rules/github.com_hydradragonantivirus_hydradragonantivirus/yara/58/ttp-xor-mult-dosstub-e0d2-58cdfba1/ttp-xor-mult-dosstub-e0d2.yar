rule TTP_XOR_MULT_DOSStub_e0d2 {
  strings:
    $key_e0d2 = { b4 ba [2] c0 a2 [2] 87 a0 [2] c0 b1 [2] 8e bd [2] 82 b7 [2] 95 bc [2] 8e f2 [2] b3 }

  condition:
    any of them
}