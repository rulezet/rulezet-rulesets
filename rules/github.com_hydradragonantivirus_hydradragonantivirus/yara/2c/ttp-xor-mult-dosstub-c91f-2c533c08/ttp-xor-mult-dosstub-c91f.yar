rule TTP_XOR_MULT_DOSStub_c91f {
  strings:
    $key_c91f = { 9d 77 [2] e9 6f [2] ae 6d [2] e9 7c [2] a7 70 [2] ab 7a [2] bc 71 [2] a7 3f [2] 9a }

  condition:
    any of them
}