rule TTP_XOR_MULT_DOSStub_e6fa {
  strings:
    $key_e6fa = { b2 92 [2] c6 8a [2] 81 88 [2] c6 99 [2] 88 95 [2] 84 9f [2] 93 94 [2] 88 da [2] b5 }

  condition:
    any of them
}