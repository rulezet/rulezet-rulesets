rule TTP_XOR_MULT_DOSStub_ef41 {
  strings:
    $key_ef41 = { bb 29 [2] cf 31 [2] 88 33 [2] cf 22 [2] 81 2e [2] 8d 24 [2] 9a 2f [2] 81 61 [2] bc }

  condition:
    any of them
}