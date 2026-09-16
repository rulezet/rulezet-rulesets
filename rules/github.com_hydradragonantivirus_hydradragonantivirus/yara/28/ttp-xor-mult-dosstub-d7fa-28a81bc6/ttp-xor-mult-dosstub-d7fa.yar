rule TTP_XOR_MULT_DOSStub_d7fa {
  strings:
    $key_d7fa = { 83 92 [2] f7 8a [2] b0 88 [2] f7 99 [2] b9 95 [2] b5 9f [2] a2 94 [2] b9 da [2] 84 }

  condition:
    any of them
}