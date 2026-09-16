rule TTP_XOR_MULT_DOSStub_04fa {
  strings:
    $key_04fa = { 50 92 [2] 24 8a [2] 63 88 [2] 24 99 [2] 6a 95 [2] 66 9f [2] 71 94 [2] 6a da [2] 57 }

  condition:
    any of them
}