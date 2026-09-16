rule TTP_XOR_MULT_DOSStub_e6f6 {
  strings:
    $key_e6f6 = { b2 9e [2] c6 86 [2] 81 84 [2] c6 95 [2] 88 99 [2] 84 93 [2] 93 98 [2] 88 d6 [2] b5 }

  condition:
    any of them
}