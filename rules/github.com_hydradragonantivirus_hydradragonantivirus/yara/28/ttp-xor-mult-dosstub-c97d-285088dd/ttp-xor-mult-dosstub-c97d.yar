rule TTP_XOR_MULT_DOSStub_c97d {
  strings:
    $key_c97d = { 9d 15 [2] e9 0d [2] ae 0f [2] e9 1e [2] a7 12 [2] ab 18 [2] bc 13 [2] a7 5d [2] 9a }

  condition:
    any of them
}