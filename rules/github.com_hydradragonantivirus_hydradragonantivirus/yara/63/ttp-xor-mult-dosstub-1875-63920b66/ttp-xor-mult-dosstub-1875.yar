rule TTP_XOR_MULT_DOSStub_1875 {
  strings:
    $key_1875 = { 4c 1d [2] 38 05 [2] 7f 07 [2] 38 16 [2] 76 1a [2] 7a 10 [2] 6d 1b [2] 76 55 [2] 4b }

  condition:
    any of them
}