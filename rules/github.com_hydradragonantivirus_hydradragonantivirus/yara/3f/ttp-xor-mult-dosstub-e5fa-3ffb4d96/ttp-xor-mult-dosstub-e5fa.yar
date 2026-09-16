rule TTP_XOR_MULT_DOSStub_e5fa {
  strings:
    $key_e5fa = { b1 92 [2] c5 8a [2] 82 88 [2] c5 99 [2] 8b 95 [2] 87 9f [2] 90 94 [2] 8b da [2] b6 }

  condition:
    any of them
}