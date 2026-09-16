rule TTP_XOR_MULT_DOSStub_ef5d {
  strings:
    $key_ef5d = { bb 35 [2] cf 2d [2] 88 2f [2] cf 3e [2] 81 32 [2] 8d 38 [2] 9a 33 [2] 81 7d [2] bc }

  condition:
    any of them
}