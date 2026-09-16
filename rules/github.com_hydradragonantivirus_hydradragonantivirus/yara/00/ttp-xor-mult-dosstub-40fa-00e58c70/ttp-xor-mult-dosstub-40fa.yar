rule TTP_XOR_MULT_DOSStub_40fa {
  strings:
    $key_40fa = { 14 92 [2] 60 8a [2] 27 88 [2] 60 99 [2] 2e 95 [2] 22 9f [2] 35 94 [2] 2e da [2] 13 }

  condition:
    any of them
}