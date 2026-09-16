rule TTP_XOR_MULT_DOSStub_c962 {
  strings:
    $key_c962 = { 9d 0a [2] e9 12 [2] ae 10 [2] e9 01 [2] a7 0d [2] ab 07 [2] bc 0c [2] a7 42 [2] 9a }

  condition:
    any of them
}