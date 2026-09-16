rule TTP_XOR_MULT_DOSStub_c94e {
  strings:
    $key_c94e = { 9d 26 [2] e9 3e [2] ae 3c [2] e9 2d [2] a7 21 [2] ab 2b [2] bc 20 [2] a7 6e [2] 9a }

  condition:
    any of them
}