rule TTP_XOR_MULT_DOSStub_1859 {
  strings:
    $key_1859 = { 4c 31 [2] 38 29 [2] 7f 2b [2] 38 3a [2] 76 36 [2] 7a 3c [2] 6d 37 [2] 76 79 [2] 4b }

  condition:
    any of them
}