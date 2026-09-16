rule TTP_XOR_MULT_DOSStub_c9ee {
  strings:
    $key_c9ee = { 9d 86 [2] e9 9e [2] ae 9c [2] e9 8d [2] a7 81 [2] ab 8b [2] bc 80 [2] a7 ce [2] 9a }

  condition:
    any of them
}