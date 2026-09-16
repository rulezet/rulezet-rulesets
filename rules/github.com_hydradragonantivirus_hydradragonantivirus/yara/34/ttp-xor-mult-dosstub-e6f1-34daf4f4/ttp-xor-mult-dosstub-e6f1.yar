rule TTP_XOR_MULT_DOSStub_e6f1 {
  strings:
    $key_e6f1 = { b2 99 [2] c6 81 [2] 81 83 [2] c6 92 [2] 88 9e [2] 84 94 [2] 93 9f [2] 88 d1 [2] b5 }

  condition:
    any of them
}