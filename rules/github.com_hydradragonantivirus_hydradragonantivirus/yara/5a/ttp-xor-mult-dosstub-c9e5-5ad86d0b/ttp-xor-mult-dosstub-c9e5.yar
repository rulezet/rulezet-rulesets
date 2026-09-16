rule TTP_XOR_MULT_DOSStub_c9e5 {
  strings:
    $key_c9e5 = { 9d 8d [2] e9 95 [2] ae 97 [2] e9 86 [2] a7 8a [2] ab 80 [2] bc 8b [2] a7 c5 [2] 9a }

  condition:
    any of them
}