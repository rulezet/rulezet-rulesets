rule TTP_XOR_MULT_DOSStub_c90a {
  strings:
    $key_c90a = { 9d 62 [2] e9 7a [2] ae 78 [2] e9 69 [2] a7 65 [2] ab 6f [2] bc 64 [2] a7 2a [2] 9a }

  condition:
    any of them
}