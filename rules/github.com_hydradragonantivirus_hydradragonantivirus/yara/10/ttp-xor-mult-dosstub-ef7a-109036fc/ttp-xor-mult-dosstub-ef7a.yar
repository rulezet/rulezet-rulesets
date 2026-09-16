rule TTP_XOR_MULT_DOSStub_ef7a {
  strings:
    $key_ef7a = { bb 12 [2] cf 0a [2] 88 08 [2] cf 19 [2] 81 15 [2] 8d 1f [2] 9a 14 [2] 81 5a [2] bc }

  condition:
    any of them
}