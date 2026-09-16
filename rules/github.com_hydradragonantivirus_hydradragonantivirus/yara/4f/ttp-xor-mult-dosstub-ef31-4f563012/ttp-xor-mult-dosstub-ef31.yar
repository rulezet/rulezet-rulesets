rule TTP_XOR_MULT_DOSStub_ef31 {
  strings:
    $key_ef31 = { bb 59 [2] cf 41 [2] 88 43 [2] cf 52 [2] 81 5e [2] 8d 54 [2] 9a 5f [2] 81 11 [2] bc }

  condition:
    any of them
}