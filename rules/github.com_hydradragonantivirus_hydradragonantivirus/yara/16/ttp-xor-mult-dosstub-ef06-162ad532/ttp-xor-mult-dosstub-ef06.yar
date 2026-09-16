rule TTP_XOR_MULT_DOSStub_ef06 {
  strings:
    $key_ef06 = { bb 6e [2] cf 76 [2] 88 74 [2] cf 65 [2] 81 69 [2] 8d 63 [2] 9a 68 [2] 81 26 [2] bc }

  condition:
    any of them
}