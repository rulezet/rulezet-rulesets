rule TTP_XOR_MULT_DOSStub_ef0a {
  strings:
    $key_ef0a = { bb 62 [2] cf 7a [2] 88 78 [2] cf 69 [2] 81 65 [2] 8d 6f [2] 9a 64 [2] 81 2a [2] bc }

  condition:
    any of them
}