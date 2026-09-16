rule TTP_XOR_MULT_DOSStub_c915 {
  strings:
    $key_c915 = { 9d 7d [2] e9 65 [2] ae 67 [2] e9 76 [2] a7 7a [2] ab 70 [2] bc 7b [2] a7 35 [2] 9a }

  condition:
    any of them
}