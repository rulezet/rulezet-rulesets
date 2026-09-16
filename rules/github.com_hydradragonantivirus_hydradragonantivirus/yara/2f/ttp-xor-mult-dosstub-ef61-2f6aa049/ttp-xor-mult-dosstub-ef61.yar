rule TTP_XOR_MULT_DOSStub_ef61 {
  strings:
    $key_ef61 = { bb 09 [2] cf 11 [2] 88 13 [2] cf 02 [2] 81 0e [2] 8d 04 [2] 9a 0f [2] 81 41 [2] bc }

  condition:
    any of them
}