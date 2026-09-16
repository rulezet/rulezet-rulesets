rule TTP_XOR_MULT_DOSStub_90fa {
  strings:
    $key_90fa = { c4 92 [2] b0 8a [2] f7 88 [2] b0 99 [2] fe 95 [2] f2 9f [2] e5 94 [2] fe da [2] c3 }

  condition:
    any of them
}