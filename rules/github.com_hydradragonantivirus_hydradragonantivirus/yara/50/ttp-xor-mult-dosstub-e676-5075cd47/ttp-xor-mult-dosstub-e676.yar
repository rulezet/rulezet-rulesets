rule TTP_XOR_MULT_DOSStub_e676 {
  strings:
    $key_e676 = { b2 1e [2] c6 06 [2] 81 04 [2] c6 15 [2] 88 19 [2] 84 13 [2] 93 18 [2] 88 56 [2] b5 }

  condition:
    any of them
}