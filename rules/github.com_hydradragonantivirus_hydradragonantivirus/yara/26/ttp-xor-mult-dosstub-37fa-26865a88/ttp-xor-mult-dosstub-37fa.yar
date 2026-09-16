rule TTP_XOR_MULT_DOSStub_37fa {
  strings:
    $key_37fa = { 63 92 [2] 17 8a [2] 50 88 [2] 17 99 [2] 59 95 [2] 55 9f [2] 42 94 [2] 59 da [2] 64 }

  condition:
    any of them
}