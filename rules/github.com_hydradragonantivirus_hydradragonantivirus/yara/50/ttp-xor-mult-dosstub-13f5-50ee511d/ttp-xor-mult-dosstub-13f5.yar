rule TTP_XOR_MULT_DOSStub_13f5 {
  strings:
    $key_13f5 = { 47 9d [2] 33 85 [2] 74 87 [2] 33 96 [2] 7d 9a [2] 71 90 [2] 66 9b [2] 7d d5 [2] 40 }

  condition:
    any of them
}