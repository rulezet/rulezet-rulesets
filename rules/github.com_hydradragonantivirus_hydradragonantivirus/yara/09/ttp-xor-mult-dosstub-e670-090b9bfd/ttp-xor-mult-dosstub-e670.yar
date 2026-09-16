rule TTP_XOR_MULT_DOSStub_e670 {
  strings:
    $key_e670 = { b2 18 [2] c6 00 [2] 81 02 [2] c6 13 [2] 88 1f [2] 84 15 [2] 93 1e [2] 88 50 [2] b5 }

  condition:
    any of them
}