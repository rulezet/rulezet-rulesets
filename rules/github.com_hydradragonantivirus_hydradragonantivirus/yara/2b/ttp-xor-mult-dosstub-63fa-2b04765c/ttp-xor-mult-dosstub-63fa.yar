rule TTP_XOR_MULT_DOSStub_63fa {
  strings:
    $key_63fa = { 37 92 [2] 43 8a [2] 04 88 [2] 43 99 [2] 0d 95 [2] 01 9f [2] 16 94 [2] 0d da [2] 30 }

  condition:
    any of them
}