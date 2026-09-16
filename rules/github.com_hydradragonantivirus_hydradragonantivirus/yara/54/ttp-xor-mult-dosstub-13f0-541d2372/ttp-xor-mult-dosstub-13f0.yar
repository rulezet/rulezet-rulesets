rule TTP_XOR_MULT_DOSStub_13f0 {
  strings:
    $key_13f0 = { 47 98 [2] 33 80 [2] 74 82 [2] 33 93 [2] 7d 9f [2] 71 95 [2] 66 9e [2] 7d d0 [2] 40 }

  condition:
    any of them
}