rule TTP_XOR_MULT_DOSStub_e5d9 {
  strings:
    $key_e5d9 = { b1 b1 [2] c5 a9 [2] 82 ab [2] c5 ba [2] 8b b6 [2] 87 bc [2] 90 b7 [2] 8b f9 [2] b6 }

  condition:
    any of them
}