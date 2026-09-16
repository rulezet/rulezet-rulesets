rule TTP_XOR_MULT_DOSStub_ef5a {
  strings:
    $key_ef5a = { bb 32 [2] cf 2a [2] 88 28 [2] cf 39 [2] 81 35 [2] 8d 3f [2] 9a 34 [2] 81 7a [2] bc }

  condition:
    any of them
}