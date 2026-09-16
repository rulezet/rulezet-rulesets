rule TTP_XOR_MULT_DOSStub_c9e1 {
  strings:
    $key_c9e1 = { 9d 89 [2] e9 91 [2] ae 93 [2] e9 82 [2] a7 8e [2] ab 84 [2] bc 8f [2] a7 c1 [2] 9a }

  condition:
    any of them
}