rule TTP_XOR_MULT_DOSStub_ef7f {
  strings:
    $key_ef7f = { bb 17 [2] cf 0f [2] 88 0d [2] cf 1c [2] 81 10 [2] 8d 1a [2] 9a 11 [2] 81 5f [2] bc }

  condition:
    any of them
}