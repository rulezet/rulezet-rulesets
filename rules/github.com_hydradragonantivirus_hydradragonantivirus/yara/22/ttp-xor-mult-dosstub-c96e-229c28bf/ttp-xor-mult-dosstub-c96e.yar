rule TTP_XOR_MULT_DOSStub_c96e {
  strings:
    $key_c96e = { 9d 06 [2] e9 1e [2] ae 1c [2] e9 0d [2] a7 01 [2] ab 0b [2] bc 00 [2] a7 4e [2] 9a }

  condition:
    any of them
}