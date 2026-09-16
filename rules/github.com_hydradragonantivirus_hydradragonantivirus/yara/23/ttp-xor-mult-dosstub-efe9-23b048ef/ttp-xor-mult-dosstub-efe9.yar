rule TTP_XOR_MULT_DOSStub_efe9 {
  strings:
    $key_efe9 = { bb 81 [2] cf 99 [2] 88 9b [2] cf 8a [2] 81 86 [2] 8d 8c [2] 9a 87 [2] 81 c9 [2] bc }

  condition:
    any of them
}