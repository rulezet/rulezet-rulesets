rule TTP_XOR_MULT_DOSStub_73fa {
  strings:
    $key_73fa = { 27 92 [2] 53 8a [2] 14 88 [2] 53 99 [2] 1d 95 [2] 11 9f [2] 06 94 [2] 1d da [2] 20 }

  condition:
    any of them
}