rule TTP_XOR_MULT_DOSStub_c905 {
  strings:
    $key_c905 = { 9d 6d [2] e9 75 [2] ae 77 [2] e9 66 [2] a7 6a [2] ab 60 [2] bc 6b [2] a7 25 [2] 9a }

  condition:
    any of them
}