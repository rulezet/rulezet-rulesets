rule TTP_XOR_MULT_DOSStub_c91e {
  strings:
    $key_c91e = { 9d 76 [2] e9 6e [2] ae 6c [2] e9 7d [2] a7 71 [2] ab 7b [2] bc 70 [2] a7 3e [2] 9a }

  condition:
    any of them
}