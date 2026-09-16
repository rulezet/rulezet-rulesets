rule TTP_XOR_MULT_DOSStub_d5fa {
  strings:
    $key_d5fa = { 81 92 [2] f5 8a [2] b2 88 [2] f5 99 [2] bb 95 [2] b7 9f [2] a0 94 [2] bb da [2] 86 }

  condition:
    any of them
}