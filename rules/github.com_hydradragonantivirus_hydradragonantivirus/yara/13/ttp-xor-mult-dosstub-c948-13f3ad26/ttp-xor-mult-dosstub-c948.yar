rule TTP_XOR_MULT_DOSStub_c948 {
  strings:
    $key_c948 = { 9d 20 [2] e9 38 [2] ae 3a [2] e9 2b [2] a7 27 [2] ab 2d [2] bc 26 [2] a7 68 [2] 9a }

  condition:
    any of them
}