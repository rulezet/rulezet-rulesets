rule TTP_XOR_MULT_DOSStub_ef51 {
  strings:
    $key_ef51 = { bb 39 [2] cf 21 [2] 88 23 [2] cf 32 [2] 81 3e [2] 8d 34 [2] 9a 3f [2] 81 71 [2] bc }

  condition:
    any of them
}