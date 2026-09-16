rule TTP_XOR_MULT_DOSStub_ef5c {
  strings:
    $key_ef5c = { bb 34 [2] cf 2c [2] 88 2e [2] cf 3f [2] 81 33 [2] 8d 39 [2] 9a 32 [2] 81 7c [2] bc }

  condition:
    any of them
}