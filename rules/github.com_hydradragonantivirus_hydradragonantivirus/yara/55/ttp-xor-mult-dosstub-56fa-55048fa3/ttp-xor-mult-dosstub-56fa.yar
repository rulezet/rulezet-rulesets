rule TTP_XOR_MULT_DOSStub_56fa {
  strings:
    $key_56fa = { 02 92 [2] 76 8a [2] 31 88 [2] 76 99 [2] 38 95 [2] 34 9f [2] 23 94 [2] 38 da [2] 05 }

  condition:
    any of them
}