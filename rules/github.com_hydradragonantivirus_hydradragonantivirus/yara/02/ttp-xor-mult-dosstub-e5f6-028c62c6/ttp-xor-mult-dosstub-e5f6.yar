rule TTP_XOR_MULT_DOSStub_e5f6 {
  strings:
    $key_e5f6 = { b1 9e [2] c5 86 [2] 82 84 [2] c5 95 [2] 8b 99 [2] 87 93 [2] 90 98 [2] 8b d6 [2] b6 }

  condition:
    any of them
}