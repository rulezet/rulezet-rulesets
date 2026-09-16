rule TTP_XOR_MULT_DOSStub_16fa {
  strings:
    $key_16fa = { 42 92 [2] 36 8a [2] 71 88 [2] 36 99 [2] 78 95 [2] 74 9f [2] 63 94 [2] 78 da [2] 45 }

  condition:
    any of them
}