rule TTP_XOR_MULT_DOSStub_ef3f {
  strings:
    $key_ef3f = { bb 57 [2] cf 4f [2] 88 4d [2] cf 5c [2] 81 50 [2] 8d 5a [2] 9a 51 [2] 81 1f [2] bc }

  condition:
    any of them
}