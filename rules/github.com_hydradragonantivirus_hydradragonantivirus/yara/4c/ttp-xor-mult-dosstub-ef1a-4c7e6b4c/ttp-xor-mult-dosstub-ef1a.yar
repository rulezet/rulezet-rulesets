rule TTP_XOR_MULT_DOSStub_ef1a {
  strings:
    $key_ef1a = { bb 72 [2] cf 6a [2] 88 68 [2] cf 79 [2] 81 75 [2] 8d 7f [2] 9a 74 [2] 81 3a [2] bc }

  condition:
    any of them
}