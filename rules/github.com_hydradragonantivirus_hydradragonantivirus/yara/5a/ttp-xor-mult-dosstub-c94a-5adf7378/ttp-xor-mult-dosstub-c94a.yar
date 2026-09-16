rule TTP_XOR_MULT_DOSStub_c94a {
  strings:
    $key_c94a = { 9d 22 [2] e9 3a [2] ae 38 [2] e9 29 [2] a7 25 [2] ab 2f [2] bc 24 [2] a7 6a [2] 9a }

  condition:
    any of them
}