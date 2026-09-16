rule TTP_XOR_MULT_DOSStub_e09a {
  strings:
    $key_e09a = { b4 f2 [2] c0 ea [2] 87 e8 [2] c0 f9 [2] 8e f5 [2] 82 ff [2] 95 f4 [2] 8e ba [2] b3 }

  condition:
    any of them
}