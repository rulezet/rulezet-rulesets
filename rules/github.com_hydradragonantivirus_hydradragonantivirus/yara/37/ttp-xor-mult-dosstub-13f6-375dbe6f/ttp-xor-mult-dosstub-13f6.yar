rule TTP_XOR_MULT_DOSStub_13f6 {
  strings:
    $key_13f6 = { 47 9e [2] 33 86 [2] 74 84 [2] 33 95 [2] 7d 99 [2] 71 93 [2] 66 98 [2] 7d d6 [2] 40 }

  condition:
    any of them
}