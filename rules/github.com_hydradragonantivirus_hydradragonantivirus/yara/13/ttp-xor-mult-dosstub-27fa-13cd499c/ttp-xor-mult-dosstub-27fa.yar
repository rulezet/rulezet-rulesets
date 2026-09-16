rule TTP_XOR_MULT_DOSStub_27fa {
  strings:
    $key_27fa = { 73 92 [2] 07 8a [2] 40 88 [2] 07 99 [2] 49 95 [2] 45 9f [2] 52 94 [2] 49 da [2] 74 }

  condition:
    any of them
}