rule TTP_XOR_MULT_DOSStub_ef28 {
  strings:
    $key_ef28 = { bb 40 [2] cf 58 [2] 88 5a [2] cf 4b [2] 81 47 [2] 8d 4d [2] 9a 46 [2] 81 08 [2] bc }

  condition:
    any of them
}