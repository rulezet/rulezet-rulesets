rule TTP_XOR_MULT_DOSStub_c97e {
  strings:
    $key_c97e = { 9d 16 [2] e9 0e [2] ae 0c [2] e9 1d [2] a7 11 [2] ab 1b [2] bc 10 [2] a7 5e [2] 9a }

  condition:
    any of them
}