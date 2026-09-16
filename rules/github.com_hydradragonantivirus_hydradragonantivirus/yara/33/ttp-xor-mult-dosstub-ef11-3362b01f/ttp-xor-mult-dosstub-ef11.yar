rule TTP_XOR_MULT_DOSStub_ef11 {
  strings:
    $key_ef11 = { bb 79 [2] cf 61 [2] 88 63 [2] cf 72 [2] 81 7e [2] 8d 74 [2] 9a 7f [2] 81 31 [2] bc }

  condition:
    any of them
}