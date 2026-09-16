rule TTP_XOR_MULT_DOSStub_ef13 {
  strings:
    $key_ef13 = { bb 7b [2] cf 63 [2] 88 61 [2] cf 70 [2] 81 7c [2] 8d 76 [2] 9a 7d [2] 81 33 [2] bc }

  condition:
    any of them
}