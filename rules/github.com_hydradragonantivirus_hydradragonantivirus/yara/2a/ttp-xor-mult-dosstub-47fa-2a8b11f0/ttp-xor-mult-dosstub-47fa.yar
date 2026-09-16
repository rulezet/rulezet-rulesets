rule TTP_XOR_MULT_DOSStub_47fa {
  strings:
    $key_47fa = { 13 92 [2] 67 8a [2] 20 88 [2] 67 99 [2] 29 95 [2] 25 9f [2] 32 94 [2] 29 da [2] 14 }

  condition:
    any of them
}