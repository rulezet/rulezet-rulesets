rule TTP_XOR_MULT_DOSStub_c9fb {
  strings:
    $key_c9fb = { 9d 93 [2] e9 8b [2] ae 89 [2] e9 98 [2] a7 94 [2] ab 9e [2] bc 95 [2] a7 db [2] 9a }

  condition:
    any of them
}