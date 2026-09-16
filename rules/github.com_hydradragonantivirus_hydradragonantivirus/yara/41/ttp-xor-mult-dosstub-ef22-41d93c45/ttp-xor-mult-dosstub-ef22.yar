rule TTP_XOR_MULT_DOSStub_ef22 {
  strings:
    $key_ef22 = { bb 4a [2] cf 52 [2] 88 50 [2] cf 41 [2] 81 4d [2] 8d 47 [2] 9a 4c [2] 81 02 [2] bc }

  condition:
    any of them
}