rule TTP_XOR_MULT_DOSStub_ef20 {
  strings:
    $key_ef20 = { bb 48 [2] cf 50 [2] 88 52 [2] cf 43 [2] 81 4f [2] 8d 45 [2] 9a 4e [2] 81 00 [2] bc }

  condition:
    any of them
}