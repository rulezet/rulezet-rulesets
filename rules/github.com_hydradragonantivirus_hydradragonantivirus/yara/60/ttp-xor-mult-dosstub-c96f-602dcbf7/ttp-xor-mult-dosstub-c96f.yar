rule TTP_XOR_MULT_DOSStub_c96f {
  strings:
    $key_c96f = { 9d 07 [2] e9 1f [2] ae 1d [2] e9 0c [2] a7 00 [2] ab 0a [2] bc 01 [2] a7 4f [2] 9a }

  condition:
    any of them
}