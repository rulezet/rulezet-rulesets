rule TTP_XOR_MULT_DOSStub_ef76 {
  strings:
    $key_ef76 = { bb 1e [2] cf 06 [2] 88 04 [2] cf 15 [2] 81 19 [2] 8d 13 [2] 9a 18 [2] 81 56 [2] bc }

  condition:
    any of them
}