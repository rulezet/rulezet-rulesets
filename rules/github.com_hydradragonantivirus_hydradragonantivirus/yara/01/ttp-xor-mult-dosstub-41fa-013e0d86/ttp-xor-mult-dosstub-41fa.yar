rule TTP_XOR_MULT_DOSStub_41fa {
  strings:
    $key_41fa = { 15 92 [2] 61 8a [2] 26 88 [2] 61 99 [2] 2f 95 [2] 23 9f [2] 34 94 [2] 2f da [2] 12 }

  condition:
    any of them
}