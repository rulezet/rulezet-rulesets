rule TTP_XOR_MULT_DOSStub_c93e {
  strings:
    $key_c93e = { 9d 56 [2] e9 4e [2] ae 4c [2] e9 5d [2] a7 51 [2] ab 5b [2] bc 50 [2] a7 1e [2] 9a }

  condition:
    any of them
}