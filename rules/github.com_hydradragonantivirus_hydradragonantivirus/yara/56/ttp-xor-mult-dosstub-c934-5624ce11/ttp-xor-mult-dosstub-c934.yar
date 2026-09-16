rule TTP_XOR_MULT_DOSStub_c934 {
  strings:
    $key_c934 = { 9d 5c [2] e9 44 [2] ae 46 [2] e9 57 [2] a7 5b [2] ab 51 [2] bc 5a [2] a7 14 [2] 9a }

  condition:
    any of them
}