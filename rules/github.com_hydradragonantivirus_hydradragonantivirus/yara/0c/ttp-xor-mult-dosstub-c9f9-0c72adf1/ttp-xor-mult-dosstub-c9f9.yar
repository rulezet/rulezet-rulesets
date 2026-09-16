rule TTP_XOR_MULT_DOSStub_c9f9 {
  strings:
    $key_c9f9 = { 9d 91 [2] e9 89 [2] ae 8b [2] e9 9a [2] a7 96 [2] ab 9c [2] bc 97 [2] a7 d9 [2] 9a }

  condition:
    any of them
}