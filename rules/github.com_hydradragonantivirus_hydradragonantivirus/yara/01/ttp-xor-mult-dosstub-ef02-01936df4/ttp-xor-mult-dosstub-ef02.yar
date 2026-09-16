rule TTP_XOR_MULT_DOSStub_ef02 {
  strings:
    $key_ef02 = { bb 6a [2] cf 72 [2] 88 70 [2] cf 61 [2] 81 6d [2] 8d 67 [2] 9a 6c [2] 81 22 [2] bc }

  condition:
    any of them
}