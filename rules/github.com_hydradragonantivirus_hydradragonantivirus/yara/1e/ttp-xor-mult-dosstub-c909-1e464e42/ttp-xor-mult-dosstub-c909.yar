rule TTP_XOR_MULT_DOSStub_c909 {
  strings:
    $key_c909 = { 9d 61 [2] e9 79 [2] ae 7b [2] e9 6a [2] a7 66 [2] ab 6c [2] bc 67 [2] a7 29 [2] 9a }

  condition:
    any of them
}