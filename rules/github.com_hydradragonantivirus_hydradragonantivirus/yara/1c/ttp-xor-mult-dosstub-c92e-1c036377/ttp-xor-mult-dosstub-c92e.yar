rule TTP_XOR_MULT_DOSStub_c92e {
  strings:
    $key_c92e = { 9d 46 [2] e9 5e [2] ae 5c [2] e9 4d [2] a7 41 [2] ab 4b [2] bc 40 [2] a7 0e [2] 9a }

  condition:
    any of them
}