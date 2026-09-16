rule TTP_XOR_MULT_DOSStub_545a {
  strings:
    $key_545a = { 00 32 [2] 74 2a [2] 33 28 [2] 74 39 [2] 3a 35 [2] 36 3f [2] 21 34 [2] 3a 7a [2] 07 }

  condition:
    any of them
}