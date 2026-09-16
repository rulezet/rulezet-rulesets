rule TTP_XOR_MULT_DOSStub_c9e3 {
  strings:
    $key_c9e3 = { 9d 8b [2] e9 93 [2] ae 91 [2] e9 80 [2] a7 8c [2] ab 86 [2] bc 8d [2] a7 c3 [2] 9a }

  condition:
    any of them
}