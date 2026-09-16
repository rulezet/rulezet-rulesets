rule TTP_XOR_MULT_DOSStub_13f8 {
  strings:
    $key_13f8 = { 47 90 [2] 33 88 [2] 74 8a [2] 33 9b [2] 7d 97 [2] 71 9d [2] 66 96 [2] 7d d8 [2] 40 }

  condition:
    any of them
}