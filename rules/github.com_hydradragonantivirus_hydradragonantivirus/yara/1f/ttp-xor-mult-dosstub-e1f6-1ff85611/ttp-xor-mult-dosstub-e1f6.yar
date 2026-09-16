rule TTP_XOR_MULT_DOSStub_e1f6 {
  strings:
    $key_e1f6 = { b5 9e [2] c1 86 [2] 86 84 [2] c1 95 [2] 8f 99 [2] 83 93 [2] 94 98 [2] 8f d6 [2] b2 }

  condition:
    any of them
}