rule TTP_XOR_MULT_DOSStub_ef5f {
  strings:
    $key_ef5f = { bb 37 [2] cf 2f [2] 88 2d [2] cf 3c [2] 81 30 [2] 8d 3a [2] 9a 31 [2] 81 7f [2] bc }

  condition:
    any of them
}