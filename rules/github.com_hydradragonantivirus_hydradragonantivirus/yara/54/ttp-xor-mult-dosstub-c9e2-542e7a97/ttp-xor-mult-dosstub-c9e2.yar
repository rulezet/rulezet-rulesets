rule TTP_XOR_MULT_DOSStub_c9e2 {
  strings:
    $key_c9e2 = { 9d 8a [2] e9 92 [2] ae 90 [2] e9 81 [2] a7 8d [2] ab 87 [2] bc 8c [2] a7 c2 [2] 9a }

  condition:
    any of them
}