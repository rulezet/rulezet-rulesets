rule TTP_XOR_MULT_DOSStub_ef12 {
  strings:
    $key_ef12 = { bb 7a [2] cf 62 [2] 88 60 [2] cf 71 [2] 81 7d [2] 8d 77 [2] 9a 7c [2] 81 32 [2] bc }

  condition:
    any of them
}