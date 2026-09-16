rule TTP_XOR_MULT_DOSStub_7a28 {
  strings:
    $key_7a28 = { 2e 40 [2] 5a 58 [2] 1d 5a [2] 5a 4b [2] 14 47 [2] 18 4d [2] 0f 46 [2] 14 08 [2] 29 }

  condition:
    any of them
}