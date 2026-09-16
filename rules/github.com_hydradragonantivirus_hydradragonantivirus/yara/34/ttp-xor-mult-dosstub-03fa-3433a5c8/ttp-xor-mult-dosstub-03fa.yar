rule TTP_XOR_MULT_DOSStub_03fa {
  strings:
    $key_03fa = { 57 92 [2] 23 8a [2] 64 88 [2] 23 99 [2] 6d 95 [2] 61 9f [2] 76 94 [2] 6d da [2] 50 }

  condition:
    any of them
}