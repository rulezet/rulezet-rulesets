rule TTP_XOR_MULT_DOSStub_c9fe {
  strings:
    $key_c9fe = { 9d 96 [2] e9 8e [2] ae 8c [2] e9 9d [2] a7 91 [2] ab 9b [2] bc 90 [2] a7 de [2] 9a }

  condition:
    any of them
}