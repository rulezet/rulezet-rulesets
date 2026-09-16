rule TTP_XOR_MULT_DOSStub_c938 {
  strings:
    $key_c938 = { 9d 50 [2] e9 48 [2] ae 4a [2] e9 5b [2] a7 57 [2] ab 5d [2] bc 56 [2] a7 18 [2] 9a }

  condition:
    any of them
}