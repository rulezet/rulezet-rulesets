rule TTP_XOR_MULT_DOSStub_e6e2 {
  strings:
    $key_e6e2 = { b2 8a [2] c6 92 [2] 81 90 [2] c6 81 [2] 88 8d [2] 84 87 [2] 93 8c [2] 88 c2 [2] b5 }

  condition:
    any of them
}