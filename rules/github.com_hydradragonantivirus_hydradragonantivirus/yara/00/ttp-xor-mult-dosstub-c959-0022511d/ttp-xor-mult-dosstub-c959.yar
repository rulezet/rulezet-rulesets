rule TTP_XOR_MULT_DOSStub_c959 {
  strings:
    $key_c959 = { 9d 31 [2] e9 29 [2] ae 2b [2] e9 3a [2] a7 36 [2] ab 3c [2] bc 37 [2] a7 79 [2] 9a }

  condition:
    any of them
}