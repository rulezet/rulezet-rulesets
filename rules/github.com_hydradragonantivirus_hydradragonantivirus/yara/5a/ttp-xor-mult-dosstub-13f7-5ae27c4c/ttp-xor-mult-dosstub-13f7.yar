rule TTP_XOR_MULT_DOSStub_13f7 {
  strings:
    $key_13f7 = { 47 9f [2] 33 87 [2] 74 85 [2] 33 94 [2] 7d 98 [2] 71 92 [2] 66 99 [2] 7d d7 [2] 40 }

  condition:
    any of them
}