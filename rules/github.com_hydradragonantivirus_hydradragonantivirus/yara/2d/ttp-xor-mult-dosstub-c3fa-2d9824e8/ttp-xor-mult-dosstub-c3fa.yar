rule TTP_XOR_MULT_DOSStub_c3fa {
  strings:
    $key_c3fa = { 97 92 [2] e3 8a [2] a4 88 [2] e3 99 [2] ad 95 [2] a1 9f [2] b6 94 [2] ad da [2] 90 }

  condition:
    any of them
}