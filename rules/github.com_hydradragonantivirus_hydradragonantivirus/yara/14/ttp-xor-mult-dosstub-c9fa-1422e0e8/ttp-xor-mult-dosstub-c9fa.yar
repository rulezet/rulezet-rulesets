rule TTP_XOR_MULT_DOSStub_c9fa {
  strings:
    $key_c9fa = { 9d 92 [2] e9 8a [2] ae 88 [2] e9 99 [2] a7 95 [2] ab 9f [2] bc 94 [2] a7 da [2] 9a }

  condition:
    any of them
}