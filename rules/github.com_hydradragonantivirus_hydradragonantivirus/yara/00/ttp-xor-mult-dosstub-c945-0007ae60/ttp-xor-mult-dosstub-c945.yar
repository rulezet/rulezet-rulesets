rule TTP_XOR_MULT_DOSStub_c945 {
  strings:
    $key_c945 = { 9d 2d [2] e9 35 [2] ae 37 [2] e9 26 [2] a7 2a [2] ab 20 [2] bc 2b [2] a7 65 [2] 9a }

  condition:
    any of them
}