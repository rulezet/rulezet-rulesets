rule TTP_XOR_MULT_DOSStub_ef58 {
  strings:
    $key_ef58 = { bb 30 [2] cf 28 [2] 88 2a [2] cf 3b [2] 81 37 [2] 8d 3d [2] 9a 36 [2] 81 78 [2] bc }

  condition:
    any of them
}