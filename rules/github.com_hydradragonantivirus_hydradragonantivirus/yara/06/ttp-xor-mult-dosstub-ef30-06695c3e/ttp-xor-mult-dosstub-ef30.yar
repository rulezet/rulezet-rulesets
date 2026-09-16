rule TTP_XOR_MULT_DOSStub_ef30 {
  strings:
    $key_ef30 = { bb 58 [2] cf 40 [2] 88 42 [2] cf 53 [2] 81 5f [2] 8d 55 [2] 9a 5e [2] 81 10 [2] bc }

  condition:
    any of them
}