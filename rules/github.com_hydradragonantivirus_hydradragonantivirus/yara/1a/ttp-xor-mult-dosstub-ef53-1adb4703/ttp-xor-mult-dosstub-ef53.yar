rule TTP_XOR_MULT_DOSStub_ef53 {
  strings:
    $key_ef53 = { bb 3b [2] cf 23 [2] 88 21 [2] cf 30 [2] 81 3c [2] 8d 36 [2] 9a 3d [2] 81 73 [2] bc }

  condition:
    any of them
}