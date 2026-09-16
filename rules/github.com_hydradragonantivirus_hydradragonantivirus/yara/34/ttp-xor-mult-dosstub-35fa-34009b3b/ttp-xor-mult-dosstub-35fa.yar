rule TTP_XOR_MULT_DOSStub_35fa {
  strings:
    $key_35fa = { 61 92 [2] 15 8a [2] 52 88 [2] 15 99 [2] 5b 95 [2] 57 9f [2] 40 94 [2] 5b da [2] 66 }

  condition:
    any of them
}