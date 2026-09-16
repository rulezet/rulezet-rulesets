rule TTP_XOR_MULT_DOSStub_c965 {
  strings:
    $key_c965 = { 9d 0d [2] e9 15 [2] ae 17 [2] e9 06 [2] a7 0a [2] ab 00 [2] bc 0b [2] a7 45 [2] 9a }

  condition:
    any of them
}