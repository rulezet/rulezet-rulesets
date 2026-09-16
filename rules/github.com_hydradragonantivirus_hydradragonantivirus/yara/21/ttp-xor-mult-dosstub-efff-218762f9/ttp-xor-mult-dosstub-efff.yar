rule TTP_XOR_MULT_DOSStub_efff {
  strings:
    $key_efff = { bb 97 [2] cf 8f [2] 88 8d [2] cf 9c [2] 81 90 [2] 8d 9a [2] 9a 91 [2] 81 df [2] bc }

  condition:
    any of them
}